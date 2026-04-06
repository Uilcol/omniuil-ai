"""
QSEC Orchestrator — Orquestrador do sistema multi-agente.

O Orchestrator é o cérebro do sistema:
  - Roteia tarefas para o agente correto
  - Coordena workflows multi-agente (ex: scan → analysis → remediation)
  - Mantém o loop de monitoramento contínuo
  - Gerencia o ciclo de vida dos agentes
  - Expõe a API pública do sistema

Arquitetura:
  AgentBus → despacha mensagens entre agentes
  SharedMemory → estado compartilhado
  Orchestrator → coordena tudo

Workflows disponíveis:
  1. full_security_audit   → scan + analysis + remediation plan
  2. continuous_monitoring → watch loop + auto-scan on change
  3. incident_response     → immediate containment + report
  4. supply_chain_security → sbom + sign + attest
  5. key_lifecycle         → rotate + revoke + status
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agents.analysis_agent import AnalysisAgent
from agents.incident_agent import IncidentAgent
from agents.monitoring_agent import MonitoringAgent
from agents.remediation_agent import RemediationAgent
from agents.scanner_agent import ScannerAgent
from memory.shared_memory import SharedMemory
from tools.qsec_tools import execute_tool

console = Console()


class AgentBus:
    """
    Barramento de mensagens entre agentes.
    Permite que agentes se comuniquem de forma desacoplada.
    """

    def __init__(self):
        self._subscribers: dict[str, list] = {}
        self._queue: asyncio.Queue = asyncio.Queue()

    async def publish(self, topic: str, message: dict) -> None:
        await self._queue.put({"topic": topic, "message": message, "ts": time.time()})

    async def dispatch_pending(self) -> int:
        count = 0
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                handlers = self._subscribers.get(item["topic"], [])
                for handler in handlers:
                    await handler(item["message"])
                count += 1
            except asyncio.QueueEmpty:
                break
        return count

    def subscribe(self, topic: str, handler) -> None:
        self._subscribers.setdefault(topic, []).append(handler)


class QsecOrchestrator:
    """
    Orquestrador principal do sistema QSEC multi-agente.
    """

    def __init__(self):
        self.memory     = SharedMemory()
        self.bus        = AgentBus()

        # Instancia todos os agentes
        self.scanner    = ScannerAgent(self.memory)
        self.analyst    = AnalysisAgent(self.memory)
        self.remediator = RemediationAgent(self.memory)
        self.monitor    = MonitoringAgent(self.memory)
        self.incident   = IncidentAgent(self.memory)

        self._monitoring_task: asyncio.Task | None = None
        self._setup_bus_subscriptions()

    def _setup_bus_subscriptions(self) -> None:
        """Conecta agentes ao barramento de mensagens."""

        async def on_critical_finding(msg: dict):
            """Quando um finding CRITICAL é detectado → aciona IncidentAgent."""
            if msg.get("rule_id") in ("QSC-020", "QSC-030"):
                await self.incident.respond(
                    incident_type="hardcoded_cred" if msg["rule_id"] == "QSC-030" else "jwt_none",
                    description=msg.get("description", "Critical finding detected"),
                    context=msg,
                )

        async def on_key_expiry(msg: dict):
            """Quando uma chave está prestes a vencer → força rotação."""
            execute_tool("rotate_keys", {"reason": f"Preventive rotation: {msg.get('reason', '')}"})

        self.bus.subscribe("critical_finding", on_critical_finding)
        self.bus.subscribe("key_expiry",       on_key_expiry)

    # ── Workflows Públicos ────────────────────────────────────────────────────

    async def full_security_audit(
        self,
        project_path: str,
        auto_remediate: bool = False,
    ) -> dict:
        """
        Workflow 1: Auditoria completa de segurança.

        Fluxo:
          ScannerAgent → AnalysisAgent → [RemediationAgent]
        """
        start = time.time()

        console.print(Panel(
            f"[bold cyan]🔍 QSEC Full Security Audit[/bold cyan]\n"
            f"Project: [yellow]{project_path}[/yellow]\n"
            f"Auto-remediate: [{'green' if auto_remediate else 'red'}]{auto_remediate}[/]",
            title="QSEC Multi-Agent System",
        ))

        # ── Etapa 1: Scan ─────────────────────────────────────────────────────
        console.print("\n[bold blue]▶ Step 1/3: ScannerAgent scanning...[/bold blue]")
        scan_result = await self.scanner.scan_project(project_path)
        findings    = await self.memory.get_unpatched_findings()

        self._print_findings_table(findings)

        # Publica findings críticos no bus
        for f in findings:
            if f.get("severity") == "CRITICAL":
                await self.bus.publish("critical_finding", f)
        await self.bus.dispatch_pending()

        # ── Etapa 2: Análise ─────────────────────────────────────────────────
        console.print("\n[bold blue]▶ Step 2/3: AnalysisAgent analyzing...[/bold blue]")
        analysis_result = await self.analyst.analyze(findings, {"project_path": project_path})
        console.print(Panel(analysis_result["analysis"][:1500], title="📊 Security Analysis"))

        # ── Etapa 3: Remediação (opcional) ───────────────────────────────────
        remediation_result = None
        if auto_remediate and findings:
            console.print("\n[bold blue]▶ Step 3/3: RemediationAgent applying patches...[/bold blue]")
            remediation_result = await self.remediator.remediate(findings, auto_apply=True)
            console.print(Panel(remediation_result["report"][:1000], title="🔧 Remediation Report"))
        else:
            console.print("\n[dim]Step 3/3: Remediation skipped (auto_remediate=False)[/dim]")

        elapsed = round(time.time() - start, 1)
        snapshot = await self.memory.snapshot()

        report = {
            "workflow":          "full_security_audit",
            "project_path":      project_path,
            "elapsed_secs":      elapsed,
            "findings_total":    len(findings),
            "critical_count":    sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count":        sum(1 for f in findings if f.get("severity") == "HIGH"),
            "scan_result":       scan_result,
            "analysis_result":   analysis_result,
            "remediation_result": remediation_result,
            "memory_snapshot":   snapshot,
        }

        self._print_final_summary(report)
        self.memory.save_to_disk(Path("./qsec-out/state.json"))
        return report

    async def continuous_monitoring(
        self,
        watch_paths: list[str],
        interval_secs: int = 30,
    ) -> None:
        """
        Workflow 2: Monitoramento contínuo.

        Loop eterno que detecta mudanças e re-escaneia automaticamente.
        Pare com Ctrl+C.
        """
        for path in watch_paths:
            self.monitor.add_watch_path(path)

        console.print(Panel(
            f"[bold green]👁 QSEC Continuous Monitoring Started[/bold green]\n"
            f"Watching: {', '.join(watch_paths)}\n"
            f"Interval: {interval_secs}s\n"
            f"Press Ctrl+C to stop",
            title="MonitoringAgent",
        ))

        cycle = 0
        while True:
            cycle += 1
            try:
                result = await self.monitor.run_watch_cycle()
                status = result.get("status", "unknown")

                if status == "changes_detected":
                    console.print(f"[yellow]⚡ Cycle {cycle}: Changes detected in {len(result.get('changed_files', []))} file(s)[/yellow]")

                    # Re-scan automático
                    for path in watch_paths:
                        scan = await self.scanner.scan_project(path)
                        new_findings = await self.memory.get_findings_by_severity("CRITICAL")
                        if new_findings:
                            await self.bus.publish("critical_finding", new_findings[0])
                            await self.bus.dispatch_pending()

                elif status == "no_changes":
                    console.print(f"[dim]Cycle {cycle}: No changes detected[/dim]")

                # Verifica chaves periodicamente (a cada 10 ciclos)
                if cycle % 10 == 0:
                    await self.monitor.check_key_expiry()

                await asyncio.sleep(interval_secs)

            except asyncio.CancelledError:
                console.print("\n[yellow]Monitoring stopped.[/yellow]")
                break

    async def respond_to_incident(
        self,
        incident_type: str,
        description:   str,
        context:       dict | None = None,
    ) -> dict:
        """
        Workflow 3: Resposta imediata a incidente.
        """
        console.print(Panel(
            f"[bold red]🚨 INCIDENT RESPONSE INITIATED[/bold red]\n"
            f"Type: [yellow]{incident_type}[/yellow]\n"
            f"Description: {description[:100]}",
            title="IncidentAgent — URGENT",
        ))

        result = await self.incident.respond(incident_type, description, context)
        console.print(Panel(result["report"][:1500], title="📋 Incident Report"))
        self.memory.save_to_disk(Path("./qsec-out/state.json"))
        return result

    async def supply_chain_security(
        self,
        project_path: str,
        artifacts:    list[str],
        output_dir:   str = "./qsec-out",
        source_repo:  str = "",
    ) -> dict:
        """
        Workflow 4: Pipeline completo de supply chain.
        SBOM + assinatura + attestation via engine Rust.
        """
        console.print(Panel(
            f"[bold cyan]🔐 Supply Chain Security Pipeline[/bold cyan]\n"
            f"Project: {project_path}\n"
            f"Artifacts: {', '.join(artifacts) or '(none)'}",
            title="QSEC Supply Chain",
        ))

        result = execute_tool("run_full_pipeline", {
            "project_path": project_path,
            "artifacts":    artifacts,
            "output_dir":   output_dir,
            "source_repo":  source_repo,
        })

        console.print(f"[green]✅ Pipeline complete:[/green] {output_dir}")
        return result

    async def key_lifecycle(self, action: str, key_id: str = "", reason: str = "") -> dict:
        """
        Workflow 5: Gestão do ciclo de vida de chaves.
        """
        if action == "rotate":
            return execute_tool("rotate_keys", {"reason": reason or "Manual rotation"})
        elif action == "status":
            return execute_tool("get_engine_info", {})
        elif action == "revoke" and key_id:
            await self.incident.respond_to_key_compromise(key_id, reason)
            return {"revoked": True, "key_id": key_id}
        return {"error": f"Unknown action: {action}"}

    # ── Utilitários de Display ────────────────────────────────────────────────

    def _print_findings_table(self, findings: list[dict]) -> None:
        if not findings:
            console.print("[green]✅ No findings — codebase is clean![/green]")
            return

        table = Table(title=f"Crypto Findings ({len(findings)} total)")
        table.add_column("Severity", style="bold")
        table.add_column("Rule ID")
        table.add_column("Title")
        table.add_column("File:Line")

        colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}
        for f in findings[:20]:  # máximo 20 na tabela
            sev   = f.get("severity", "LOW")
            color = colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev}[/]",
                f.get("rule_id", ""),
                f.get("title", "")[:50],
                f"{Path(f.get('file','?')).name}:{f.get('line',0)}",
            )

        if len(findings) > 20:
            table.add_row("...", "...", f"and {len(findings)-20} more", "...")

        console.print(table)

    def _print_final_summary(self, report: dict) -> None:
        table = Table(title="🏁 Audit Summary")
        table.add_column("Metric")
        table.add_column("Value", style="bold")

        table.add_row("Total Findings",   str(report["findings_total"]))
        table.add_row("Critical",         f"[red]{report['critical_count']}[/red]")
        table.add_row("High",             f"[yellow]{report['high_count']}[/yellow]")
        table.add_row("Elapsed",          f"{report['elapsed_secs']}s")
        table.add_row("Patches Applied",  str(report["memory_snapshot"].get("patches_applied", 0)))
        table.add_row("Active Incidents", str(report["memory_snapshot"].get("active_incidents", 0)))

        console.print("\n")
        console.print(table)
