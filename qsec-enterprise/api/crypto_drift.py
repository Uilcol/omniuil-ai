"""
OmniUil AI v5.0 — Crypto Drift Detection
==========================================
Detecta regressões criptográficas entre scans consecutivos.
"Nunca seja surpreendido por regressão criptográfica."

Como funciona:
  1. Cada scan é salvo com timestamp no SQLite
  2. A cada novo scan, compara com o anterior
  3. Se detectar novo finding crítico: alerta via webhook/e-mail
  4. Gera relatório de drift: o que piorou, o que melhorou

Casos de uso:
  - Dev faz merge de PR com RSA → alerta em 30 min via Slack
  - Score caiu de 72 para 45 → alerta para CISO
  - Novo segredo hardcoded detectado → alerta imediato
"""
from __future__ import annotations
import json, sqlite3, hashlib
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "omniuil.db")

def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_drift_db():
    """Inicializa tabelas de histórico de scans para drift detection."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT UNIQUE NOT NULL,
            scan_path    TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            findings_hash TEXT NOT NULL,
            posture_score INTEGER,
            total_findings INTEGER,
            critical_count INTEGER,
            high_count     INTEGER,
            scanned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS drift_alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      TEXT NOT NULL,
            prev_scan_id TEXT,
            alert_type   TEXT NOT NULL,
            severity     TEXT NOT NULL,
            title        TEXT NOT NULL,
            detail       TEXT,
            new_findings_json TEXT,
            resolved_findings_json TEXT,
            score_before INTEGER,
            score_after  INTEGER,
            notified     INTEGER DEFAULT 0,
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_scan_history_path
            ON scan_history(scan_path);
        CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at
            ON scan_history(scanned_at DESC);
    """)
    conn.commit()
    conn.close()

@dataclass
class DriftReport:
    """Resultado da comparação entre dois scans."""
    has_drift: bool
    scan_id: str
    prev_scan_id: Optional[str]
    scan_path: str
    score_before: Optional[int]
    score_after: int
    score_delta: int                  # positivo = melhorou, negativo = piorou
    new_findings: list[dict]          # findings que apareceram
    resolved_findings: list[dict]     # findings que sumiram
    regression: bool                  # piorou em algo crítico
    improvement: bool                 # melhorou em algo
    alert_level: str                  # CRITICAL / HIGH / MEDIUM / LOW / NONE
    summary: str                      # frase para notificação
    scanned_at: str

def save_scan(
    scan_path: str,
    findings: list[dict],
    posture_score: int,
) -> str:
    """Salva um scan no histórico. Retorna scan_id."""
    findings_json = json.dumps(findings, sort_keys=True)
    findings_hash = hashlib.sha256(findings_json.encode()).hexdigest()[:16]
    scan_id       = f"{findings_hash}-{int(datetime.now(timezone.utc).timestamp())}"

    conn = _get_conn()
    try:
        conn.execute("""
            INSERT OR IGNORE INTO scan_history
            (scan_id, scan_path, findings_json, findings_hash,
             posture_score, total_findings, critical_count, high_count)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            scan_id, scan_path, findings_json, findings_hash,
            posture_score, len(findings),
            sum(1 for f in findings if f.get("severity","").upper() == "CRITICAL"),
            sum(1 for f in findings if f.get("severity","").upper() == "HIGH"),
        ))
        conn.commit()
    finally:
        conn.close()
    return scan_id

def get_previous_scan(scan_path: str, exclude_scan_id: str) -> Optional[dict]:
    """Retorna o scan mais recente para o mesmo path, exceto o atual."""
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM scan_history
        WHERE scan_path = ? AND scan_id != ?
        ORDER BY scanned_at DESC LIMIT 1
    """, (scan_path, exclude_scan_id)).fetchone()
    conn.close()
    return dict(row) if row else None

def _finding_key(f: dict) -> str:
    """Chave única para identificar um finding (regra + arquivo + linha)."""
    return f"{f.get('rule_id','')}::{f.get('file','')}::{f.get('line',0)}"

def detect_drift(
    scan_path: str,
    current_findings: list[dict],
    current_score: int,
) -> DriftReport:
    """
    Compara o scan atual com o anterior e detecta regressões.
    Salva automaticamente o scan atual no histórico.
    """
    init_drift_db()

    # Salva scan atual
    scan_id = save_scan(scan_path, current_findings, current_score)

    # Busca scan anterior
    prev = get_previous_scan(scan_path, scan_id)

    if not prev:
        return DriftReport(
            has_drift=False, scan_id=scan_id, prev_scan_id=None,
            scan_path=scan_path, score_before=None, score_after=current_score,
            score_delta=0, new_findings=[], resolved_findings=[],
            regression=False, improvement=False,
            alert_level="NONE",
            summary="Primeiro scan registrado para este caminho.",
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

    # Compara findings
    prev_findings  = json.loads(prev["findings_json"])
    prev_keys      = {_finding_key(f): f for f in prev_findings}
    curr_keys      = {_finding_key(f): f for f in current_findings}

    new_findings      = [f for k, f in curr_keys.items() if k not in prev_keys]
    resolved_findings = [f for k, f in prev_keys.items() if k not in curr_keys]

    score_before = prev["posture_score"]
    score_delta  = current_score - score_before

    # Classifica regressão
    new_critical = [f for f in new_findings if f.get("severity","").upper() == "CRITICAL"]
    new_high     = [f for f in new_findings if f.get("severity","").upper() == "HIGH"]
    regression   = bool(new_critical or new_high)
    improvement  = bool(resolved_findings and not new_findings)

    # Nível de alerta
    if new_critical:
        alert_level = "CRITICAL"
    elif new_high or score_delta <= -15:
        alert_level = "HIGH"
    elif new_findings or score_delta <= -5:
        alert_level = "MEDIUM"
    elif score_delta < 0:
        alert_level = "LOW"
    else:
        alert_level = "NONE"

    has_drift = bool(new_findings or resolved_findings or abs(score_delta) >= 5)

    # Gera resumo para notificação
    summary = _generate_drift_summary(
        new_findings, resolved_findings, score_before, current_score, alert_level)

    # Salva alerta se houve drift relevante
    if has_drift and alert_level not in ("NONE", "LOW"):
        _save_drift_alert(
            scan_id=scan_id,
            prev_scan_id=prev["scan_id"],
            alert_type="regression" if regression else "improvement",
            severity=alert_level,
            title=summary[:100],
            detail=f"{len(new_findings)} novos, {len(resolved_findings)} resolvidos",
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            score_before=score_before,
            score_after=current_score,
        )

    return DriftReport(
        has_drift=has_drift,
        scan_id=scan_id,
        prev_scan_id=prev["scan_id"],
        scan_path=scan_path,
        score_before=score_before,
        score_after=current_score,
        score_delta=score_delta,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        regression=regression,
        improvement=improvement,
        alert_level=alert_level,
        summary=summary,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

def _generate_drift_summary(
    new: list, resolved: list, score_before: int, score_after: int, level: str
) -> str:
    delta = score_after - score_before
    parts = []
    if new:
        critical_new = sum(1 for f in new if f.get("severity","").upper() == "CRITICAL")
        if critical_new:
            parts.append(f"⚠️ {critical_new} nova(s) vulnerabilidade(s) CRITICAL detectada(s)")
        else:
            parts.append(f"{len(new)} nova(s) vulnerabilidade(s) detectada(s)")
    if resolved:
        parts.append(f"✅ {len(resolved)} vulnerabilidade(s) resolvida(s)")
    if delta != 0:
        arrow = "↑" if delta > 0 else "↓"
        parts.append(f"Score: {score_before} → {score_after} ({arrow}{abs(delta)})")
    return " | ".join(parts) if parts else "Nenhuma mudança detectada."

def _save_drift_alert(
    scan_id, prev_scan_id, alert_type, severity, title, detail,
    new_findings, resolved_findings, score_before, score_after
):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO drift_alerts
        (scan_id, prev_scan_id, alert_type, severity, title, detail,
         new_findings_json, resolved_findings_json, score_before, score_after)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        scan_id, prev_scan_id, alert_type, severity, title, detail,
        json.dumps(new_findings), json.dumps(resolved_findings),
        score_before, score_after,
    ))
    conn.commit()
    conn.close()

def get_drift_history(scan_path: str, limit: int = 10) -> list[dict]:
    """Retorna histórico de scans para um caminho — para gráfico de evolução."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT scan_id, posture_score, total_findings, critical_count,
               high_count, scanned_at
        FROM scan_history
        WHERE scan_path = ?
        ORDER BY scanned_at DESC LIMIT ?
    """, (scan_path, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_pending_alerts(limit: int = 20) -> list[dict]:
    """Retorna alertas de drift não notificados."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT * FROM drift_alerts
        WHERE notified = 0
        ORDER BY created_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_alert_notified(alert_id: int):
    conn = _get_conn()
    conn.execute("UPDATE drift_alerts SET notified=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
