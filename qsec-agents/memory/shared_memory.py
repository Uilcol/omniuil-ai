"""
QSEC SharedMemory — Estado compartilhado entre todos os agentes.

Funciona como um "cérebro coletivo" do sistema:
  - Findings acumulados de todos os scans
  - Histórico de ações de cada agente
  - Incidentes ativos
  - Status do sistema
  - Fila de tarefas pendentes

Thread-safe via asyncio locks.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class IncidentStatus(str, Enum):
    OPEN       = "OPEN"
    MITIGATING = "MITIGATING"
    RESOLVED   = "RESOLVED"


class TaskStatus(str, Enum):
    PENDING    = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    DONE       = "DONE"
    FAILED     = "FAILED"


@dataclass
class Incident:
    id:          str
    severity:    str
    title:       str
    description: str
    created_at:  float
    status:      IncidentStatus = IncidentStatus.OPEN
    agent:       str = ""
    resolution:  str = ""
    resolved_at: float | None = None


@dataclass
class Task:
    id:          str
    type:        str          # "scan", "remediate", "rotate_keys", etc.
    payload:     dict
    created_by:  str
    created_at:  float
    status:      TaskStatus = TaskStatus.PENDING
    assigned_to: str = ""
    result:      dict | None = None
    error:       str = ""


class SharedMemory:
    """
    Estado compartilhado e thread-safe entre todos os agentes QSEC.
    """

    def __init__(self):
        self._lock = asyncio.Lock()

        # Findings de todos os scans (acumulados)
        self.findings:    list[dict]          = []
        self.scan_history: list[dict]         = []

        # Incidentes ativos e histórico
        self.incidents:   dict[str, Incident] = {}

        # Fila de tarefas
        self.tasks:       dict[str, Task]     = {}
        self._task_queue: asyncio.Queue       = asyncio.Queue()

        # Histórico de ações dos agentes
        self.agent_log:   list[dict]          = []

        # Status do sistema
        self.system_status = {
            "started_at":       time.time(),
            "last_scan_at":     None,
            "last_rotation_at": None,
            "total_findings":   0,
            "total_incidents":  0,
            "active_incidents": 0,
            "patches_applied":  0,
            "tokens_revoked":   0,
        }

        # Patches gerados aguardando aprovação
        self.pending_patches: list[dict] = []

        # Tokens revogados (compartilhado entre agentes)
        self.revoked_tokens: set[str] = set()

        # Projetos sendo monitorados
        self.monitored_paths: set[str] = set()

    # ── Findings ─────────────────────────────────────────────────────────────

    async def add_findings(self, findings: list[dict], scan_path: str, agent: str) -> None:
        async with self._lock:
            ts = time.time()
            for f in findings:
                f["_scanned_at"] = ts
                f["_scanned_by"] = agent
            self.findings.extend(findings)
            self.scan_history.append({
                "path":       scan_path,
                "count":      len(findings),
                "scanned_at": ts,
                "agent":      agent,
            })
            self.system_status["last_scan_at"]   = ts
            self.system_status["total_findings"] += len(findings)

    async def get_findings_by_severity(self, severity: str) -> list[dict]:
        async with self._lock:
            return [f for f in self.findings if f.get("severity") == severity]

    async def get_unpatched_findings(self) -> list[dict]:
        async with self._lock:
            patched_ids = {
                p["finding_id"]
                for p in self.pending_patches
                if p.get("status") == "applied"
            }
            return [
                f for f in self.findings
                if f.get("rule_id") not in patched_ids
            ]

    # ── Incidentes ───────────────────────────────────────────────────────────

    async def open_incident(
        self,
        title:       str,
        description: str,
        severity:    str,
        agent:       str,
    ) -> Incident:
        async with self._lock:
            import uuid
            inc = Incident(
                id=f"INC-{str(uuid.uuid4())[:8].upper()}",
                severity=severity,
                title=title,
                description=description,
                created_at=time.time(),
                agent=agent,
            )
            self.incidents[inc.id] = inc
            self.system_status["total_incidents"]  += 1
            self.system_status["active_incidents"] += 1
            return inc

    async def resolve_incident(self, incident_id: str, resolution: str) -> bool:
        async with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                return False
            inc.status      = IncidentStatus.RESOLVED
            inc.resolution  = resolution
            inc.resolved_at = time.time()
            self.system_status["active_incidents"] = max(
                0, self.system_status["active_incidents"] - 1
            )
            return True

    async def get_active_incidents(self) -> list[Incident]:
        async with self._lock:
            return [
                i for i in self.incidents.values()
                if i.status != IncidentStatus.RESOLVED
            ]

    # ── Tarefas ───────────────────────────────────────────────────────────────

    async def enqueue_task(
        self,
        task_type:  str,
        payload:    dict,
        created_by: str,
    ) -> Task:
        async with self._lock:
            import uuid
            task = Task(
                id=f"TASK-{str(uuid.uuid4())[:8].upper()}",
                type=task_type,
                payload=payload,
                created_by=created_by,
                created_at=time.time(),
            )
            self.tasks[task.id] = task
        await self._task_queue.put(task)
        return task

    async def next_task(self, timeout: float = 1.0) -> Task | None:
        try:
            return await asyncio.wait_for(self._task_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def complete_task(self, task_id: str, result: dict) -> None:
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.DONE
                self.tasks[task_id].result = result

    async def fail_task(self, task_id: str, error: str) -> None:
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.FAILED
                self.tasks[task_id].error  = error

    # ── Agent Log ─────────────────────────────────────────────────────────────

    async def log_action(
        self,
        agent:  str,
        action: str,
        detail: dict | None = None,
    ) -> None:
        async with self._lock:
            self.agent_log.append({
                "ts":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "agent":  agent,
                "action": action,
                "detail": detail or {},
            })

    # ── Patches ───────────────────────────────────────────────────────────────

    async def add_patch(self, patch: dict) -> None:
        async with self._lock:
            patch["added_at"] = time.time()
            patch["status"]   = "pending"
            self.pending_patches.append(patch)

    async def mark_patch_applied(self, file_path: str, rule_id: str) -> None:
        async with self._lock:
            for p in self.pending_patches:
                if p.get("file_path") == file_path and p.get("rule_id") == rule_id:
                    p["status"]      = "applied"
                    p["applied_at"]  = time.time()
                    self.system_status["patches_applied"] += 1

    # ── Tokens ────────────────────────────────────────────────────────────────

    async def revoke_token(self, jti: str) -> None:
        async with self._lock:
            self.revoked_tokens.add(jti)
            self.system_status["tokens_revoked"] += 1

    # ── Status ────────────────────────────────────────────────────────────────

    async def snapshot(self) -> dict:
        async with self._lock:
            return {
                "system":           dict(self.system_status),
                "total_findings":   len(self.findings),
                "pending_patches":  len([p for p in self.pending_patches if p.get("status") == "pending"]),
                "active_incidents": len([i for i in self.incidents.values() if i.status != IncidentStatus.RESOLVED]),
                "pending_tasks":    self._task_queue.qsize(),
                "agent_actions":    len(self.agent_log),
                "revoked_tokens":   len(self.revoked_tokens),
                "monitored_paths":  list(self.monitored_paths),
            }

    def save_to_disk(self, path: Path) -> None:
        """Persiste snapshot do estado para arquivo JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "findings":        self.findings[-500:],  # últimos 500
            "incidents":       {k: vars(v) for k, v in self.incidents.items()},
            "pending_patches": self.pending_patches,
            "agent_log":       self.agent_log[-200:],
            "system_status":   self.system_status,
        }
        path.write_text(json.dumps(data, indent=2, default=str))
