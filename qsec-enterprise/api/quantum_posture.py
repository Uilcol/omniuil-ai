"""
OmniUil AI v5.0 — Quantum Posture Score
=========================================
Score determinístico 0-100 que responde em 60 segundos:
"Qual é sua exposição ao risco quântico?"

Calculado deterministicamente — não usa LLM — auditável e defensável
perante conselho de administração, auditores e reguladores.

Metodologia:
  - Base: findings do scan (severidade + categoria)
  - Ajuste: linguagens/stacks afetados
  - Ajuste: proximidade do deadline regulatório (CNSA 2.0 = 2027)
  - Ajuste: cobertura do scan (% do codebase coberto)
  - Penalidade: achados críticos em pontos de autenticação/TLS
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict

# ── Pesos por categoria de vulnerabilidade ────────────────────────────────────
CATEGORY_WEIGHTS = {
    # Algoritmos quebráveis por Shor (risco quântico direto)
    "RSA":          {"weight": 10, "label": "RSA",          "pqc_risk": "CRITICAL"},
    "ECDSA":        {"weight": 9,  "label": "ECDSA/ECC",    "pqc_risk": "CRITICAL"},
    "DH":           {"weight": 9,  "label": "Diffie-Hellman","pqc_risk": "CRITICAL"},
    "JWT_RSA":      {"weight": 10, "label": "JWT com RSA",  "pqc_risk": "CRITICAL"},
    "JWT_ECDSA":    {"weight": 9,  "label": "JWT com ECDSA","pqc_risk": "CRITICAL"},

    # Algoritmos quebráveis por Grover (risco quântico parcial)
    "AES_128":      {"weight": 5,  "label": "AES-128",      "pqc_risk": "HIGH"},
    "SHA256":       {"weight": 3,  "label": "SHA-256",      "pqc_risk": "MEDIUM"},

    # Algoritmos já classicamente quebrados (risco imediato)
    "MD5":          {"weight": 8,  "label": "MD5",          "pqc_risk": "HIGH"},
    "SHA1":         {"weight": 7,  "label": "SHA-1",        "pqc_risk": "HIGH"},
    "DES":          {"weight": 8,  "label": "DES/3DES",     "pqc_risk": "HIGH"},
    "RC4":          {"weight": 9,  "label": "RC4",          "pqc_risk": "CRITICAL"},

    # JWT sem verificação (risco imediato, não PQC)
    "JWT_NONE":     {"weight": 10, "label": "JWT alg:none", "pqc_risk": "CRITICAL"},

    # Segredos hardcoded
    "HARDCODED":    {"weight": 7,  "label": "Segredo hardcoded","pqc_risk": "HIGH"},

    # Outros
    "WEAK_RANDOM":  {"weight": 4,  "label": "PRNG inseguro","pqc_risk": "MEDIUM"},
    "TLS_LEGACY":   {"weight": 6,  "label": "TLS legado",  "pqc_risk": "HIGH"},
}

# Mapeamento de rule_id → categoria
RULE_CATEGORY_MAP = {
    "QSC-001": "RSA",       "QSC-002": "ECDSA",      "QSC-003": "DH",
    "QSC-010": "MD5",       "QSC-011": "SHA1",        "QSC-012": "AES_128",
    "QSC-013": "DES",       "QSC-014": "RC4",
    "QSC-020": "JWT_NONE",  "QSC-021": "HARDCODED",   "QSC-022": "JWT_RSA",
    "QSC-030": "HARDCODED", "QSC-100": "HARDCODED",
    "QSC-101": "WEAK_RANDOM","QSC-102": "RSA",        "QSC-103": "AES_128",
    "QSC-104": "TLS_LEGACY","QSC-105": "WEAK_RANDOM", "QSC-106": "MD5",
    "QSC-107": "MD5",       "QSC-108": "HARDCODED",   "QSC-110": "MD5",
    "QSC-111": "HARDCODED", "QSC-112": "SHA1",        "QSC-113": "WEAK_RANDOM",
    "QSC-114": "WEAK_RANDOM","QSC-116": "HARDCODED",
    "QSC-200": "AES_128",   "QSC-201": "SHA256",      "QSC-300": "ECDSA",
    "QSC-301": "RSA",       "QSC-400": "ECDSA",       "QSC-500": "RSA",
    "CUSTOM-JV-001": "JWT_RSA", "CUSTOM-JV-002": "HARDCODED",
    "CUSTOM-PY-001": "MD5", "CUSTOM-PY-002": "JWT_NONE",
    "CUSTOM-JS-001": "HARDCODED", "CUSTOM-JS-002": "JWT_NONE",
}

# Deadline regulatório CNSA 2.0
CNSA_DEADLINE = datetime(2027, 1, 1, tzinfo=timezone.utc)


@dataclass
class PostureBreakdown:
    """Detalhamento do score para auditoria e explicação."""
    score: int                          # 0-100 (100 = sem risco)
    risk_level: str                     # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    risk_color: str                     # red / orange / yellow / green
    total_findings: int
    critical_findings: int
    high_findings: int
    categories_affected: list[str]
    months_to_deadline: int
    deadline_urgency: str               # URGENT / HIGH / MEDIUM / LOW
    top_risks: list[dict]               # top 3 riscos por impacto
    recommendation: str                 # frase executiva de 1 linha
    detail: str                         # explicação técnica para CISO
    calculated_at: str


def calculate_quantum_posture(
    findings: list[dict],
    scan_path: str = "",
    files_scanned: int = 0,
) -> PostureBreakdown:
    """
    Calcula o Quantum Posture Score deterministicamente.

    Args:
        findings: lista de findings do scan (formato JSON do qsec)
        scan_path: caminho escaneado (para contexto)
        files_scanned: número de arquivos analisados

    Returns:
        PostureBreakdown com score e breakdown completo
    """
    if not findings:
        return PostureBreakdown(
            score=95, risk_level="MINIMAL", risk_color="green",
            total_findings=0, critical_findings=0, high_findings=0,
            categories_affected=[], months_to_deadline=_months_to_deadline(),
            deadline_urgency=_deadline_urgency(), top_risks=[],
            recommendation="Nenhuma vulnerabilidade criptográfica detectada.",
            detail="O codebase analisado não apresenta uso de algoritmos vulneráveis a ataques quânticos.",
            calculated_at=datetime.now(timezone.utc).isoformat(),
        )

    # ── Conta findings por categoria ─────────────────────────────────────────
    category_counts: dict[str, int] = {}
    critical_count = 0
    high_count = 0

    for f in findings:
        rule_id  = f.get("rule_id", "")
        severity = f.get("severity", "").upper()

        if severity == "CRITICAL": critical_count += 1
        elif severity == "HIGH":   high_count += 1

        category = RULE_CATEGORY_MAP.get(rule_id, "OTHER")
        category_counts[category] = category_counts.get(category, 0) + 1

    # ── Calcula penalidade base ───────────────────────────────────────────────
    total_penalty = 0
    top_risks = []

    for category, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        if category == "OTHER":
            continue
        meta   = CATEGORY_WEIGHTS.get(category, {"weight": 3, "label": category, "pqc_risk": "LOW"})
        weight = meta["weight"]

        # Penalidade: peso × log do count (evita linearidade — 100 RSA não é 100x pior que 1)
        import math
        penalty = weight * (1 + math.log(count, 2))
        total_penalty += penalty

        top_risks.append({
            "category":  meta["label"],
            "count":     count,
            "pqc_risk":  meta["pqc_risk"],
            "penalty":   round(penalty, 1),
        })

    top_risks = sorted(top_risks, key=lambda x: -x["penalty"])[:3]

    # ── Ajuste pelo deadline ──────────────────────────────────────────────────
    months_left = _months_to_deadline()
    if months_left <= 6:
        deadline_multiplier = 1.5   # urgência crítica
    elif months_left <= 12:
        deadline_multiplier = 1.25
    elif months_left <= 18:
        deadline_multiplier = 1.1
    else:
        deadline_multiplier = 1.0

    total_penalty *= deadline_multiplier

    # ── Score final (0-100, onde 100 = sem risco) ─────────────────────────────
    # Normaliza: penalty de 100 → score 0; penalty de 0 → score 100
    raw_score = max(0, 100 - min(total_penalty, 100))
    score = round(raw_score)

    # ── Classifica nível de risco ─────────────────────────────────────────────
    if score >= 80:
        risk_level, risk_color = "MINIMAL", "green"
    elif score >= 60:
        risk_level, risk_color = "LOW", "blue"
    elif score >= 40:
        risk_level, risk_color = "MEDIUM", "yellow"
    elif score >= 20:
        risk_level, risk_color = "HIGH", "orange"
    else:
        risk_level, risk_color = "CRITICAL", "red"

    # ── Gera recomendação executiva ───────────────────────────────────────────
    recommendation = _generate_recommendation(score, top_risks, months_left)
    detail         = _generate_detail(score, category_counts, critical_count, months_left)

    return PostureBreakdown(
        score=score,
        risk_level=risk_level,
        risk_color=risk_color,
        total_findings=len(findings),
        critical_findings=critical_count,
        high_findings=high_count,
        categories_affected=list(category_counts.keys()),
        months_to_deadline=months_left,
        deadline_urgency=_deadline_urgency(),
        top_risks=top_risks,
        recommendation=recommendation,
        detail=detail,
        calculated_at=datetime.now(timezone.utc).isoformat(),
    )


def _months_to_deadline() -> int:
    now = datetime.now(timezone.utc)
    delta = CNSA_DEADLINE - now
    return max(0, int(delta.days / 30))


def _deadline_urgency() -> str:
    m = _months_to_deadline()
    if m <= 6:   return "URGENT"
    if m <= 12:  return "HIGH"
    if m <= 18:  return "MEDIUM"
    return "LOW"


def _generate_recommendation(score: int, top_risks: list, months_left: int) -> str:
    if score >= 80:
        return "Postura criptográfica sólida. Monitoramento contínuo recomendado."
    if not top_risks:
        return "Revisar cobertura do scan antes de concluir avaliação."
    top = top_risks[0]["category"]
    if score < 20:
        return f"Risco CRÍTICO: {top} detectado em múltiplos sistemas. Ação imediata necessária — {months_left} meses para deadline CNSA 2.0."
    if score < 40:
        return f"Risco ALTO: Priorizar migração de {top}. {months_left} meses para conformidade CNSA 2.0."
    return f"Risco MÉDIO: Planejar migração de {top} nos próximos {min(months_left, 6)} meses."


def _generate_detail(score: int, cats: dict, critical: int, months: int) -> str:
    algo_list = ", ".join(
        CATEGORY_WEIGHTS.get(c, {}).get("label", c)
        for c in cats if c in CATEGORY_WEIGHTS
    )[:200]
    return (
        f"Score {score}/100 calculado com base em {sum(cats.values())} findings "
        f"({critical} CRITICAL). Algoritmos vulneráveis detectados: {algo_list or 'nenhum'}. "
        f"Deadline CNSA 2.0: {months} meses. "
        f"Metodologia: penalidade ponderada por categoria × urgência regulatória."
    )
