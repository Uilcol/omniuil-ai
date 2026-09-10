"""
OmniUil AI v5.0 — Migration Intelligence
==========================================
Transforma uma lista de findings em um plano de migração priorizado
por impacto de negócio — não por severidade técnica.

"Saiba o que fazer primeiro, quanto custa e quando termina."

A diferença fundamental:
  Scanner tradicional: "Você tem 443 problemas" (paralisante)
  Migration Intelligence: "Faça isso em 3 semanas, isso em 6, isso em 12" (acionável)

Critérios de priorização (em ordem):
  1. Risco de negócio (autenticação > dados > logs)
  2. Esforço de correção (quick wins primeiro)
  3. Dependências (o que desbloqueia mais correções)
  4. Deadline regulatório (CNSA 2.0 = 2027)
"""
from __future__ import annotations
import json, math
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional

# ── Custo estimado de correção por categoria (horas de desenvolvimento) ───────
REMEDIATION_HOURS = {
    "RSA":          {"min": 8,  "max": 40,  "complexity": "MEDIUM"},
    "ECDSA":        {"min": 8,  "max": 40,  "complexity": "MEDIUM"},
    "DH":           {"min": 16, "max": 60,  "complexity": "HIGH"},
    "JWT_RSA":      {"min": 4,  "max": 16,  "complexity": "LOW"},
    "JWT_ECDSA":    {"min": 4,  "max": 16,  "complexity": "LOW"},
    "JWT_NONE":     {"min": 1,  "max": 4,   "complexity": "MINIMAL"},
    "MD5":          {"min": 2,  "max": 8,   "complexity": "LOW"},
    "SHA1":         {"min": 2,  "max": 8,   "complexity": "LOW"},
    "AES_128":      {"min": 4,  "max": 16,  "complexity": "LOW"},
    "DES":          {"min": 4,  "max": 16,  "complexity": "LOW"},
    "RC4":          {"min": 4,  "max": 12,  "complexity": "LOW"},
    "HARDCODED":    {"min": 1,  "max": 4,   "complexity": "MINIMAL"},
    "WEAK_RANDOM":  {"min": 1,  "max": 4,   "complexity": "MINIMAL"},
    "TLS_LEGACY":   {"min": 2,  "max": 8,   "complexity": "LOW"},
    "OTHER":        {"min": 4,  "max": 16,  "complexity": "MEDIUM"},
}

# Custo médio hora de dev sênior de segurança (BRL)
DEV_HOUR_COST_BRL = 400

# Mapeamento rule_id → categoria (mesmo do quantum_posture.py)
RULE_CATEGORY_MAP = {
    "QSC-001": "RSA",       "QSC-002": "ECDSA",      "QSC-003": "DH",
    "QSC-010": "MD5",       "QSC-011": "SHA1",        "QSC-012": "AES_128",
    "QSC-013": "DES",       "QSC-014": "RC4",
    "QSC-020": "JWT_NONE",  "QSC-021": "HARDCODED",   "QSC-022": "JWT_RSA",
    "QSC-030": "HARDCODED", "QSC-100": "HARDCODED",
    "QSC-101": "WEAK_RANDOM","QSC-102": "RSA",        "QSC-103": "AES_128",
    "QSC-104": "TLS_LEGACY","QSC-105": "WEAK_RANDOM","QSC-106": "MD5",
    "QSC-107": "MD5",       "QSC-108": "HARDCODED",   "QSC-110": "MD5",
    "QSC-111": "HARDCODED", "QSC-112": "SHA1",        "QSC-113": "WEAK_RANDOM",
    "QSC-114": "WEAK_RANDOM","QSC-116": "HARDCODED",
    "QSC-200": "AES_128",   "QSC-201": "SHA1",        "QSC-300": "ECDSA",
    "QSC-301": "RSA",       "QSC-400": "ECDSA",       "QSC-500": "RSA",
    "CUSTOM-JV-001": "JWT_RSA","CUSTOM-JV-002": "HARDCODED",
    "CUSTOM-PY-001": "MD5", "CUSTOM-PY-002": "JWT_NONE",
    "CUSTOM-JS-001": "HARDCODED","CUSTOM-JS-002": "JWT_NONE",
}

# Prioridade de negócio por categoria (1=mais urgente)
BUSINESS_PRIORITY = {
    "JWT_NONE":     1,   # autenticação comprometida — risco imediato
    "HARDCODED":    2,   # credenciais expostas — risco imediato
    "JWT_RSA":      3,   # autenticação quântica-vulnerável
    "JWT_ECDSA":    3,
    "RSA":          4,   # criptografia principal vulnerável
    "ECDSA":        4,
    "DH":           5,
    "RC4":          5,   # quebrado classicamente
    "DES":          6,
    "MD5":          7,
    "SHA1":         7,
    "TLS_LEGACY":   8,
    "AES_128":      9,
    "WEAK_RANDOM":  10,
    "SHA256":       11,
    "OTHER":        12,
}

@dataclass
class MigrationStep:
    """Um passo concreto e acionável no plano de migração."""
    step_number:     int
    priority:        str           # IMMEDIATE / SHORT_TERM / MEDIUM_TERM / LONG_TERM
    title:           str
    category:        str
    affected_files:  list[str]
    finding_count:   int
    effort_hours_min: int
    effort_hours_max: int
    cost_brl_min:    int
    cost_brl_max:    int
    complexity:      str
    recommendation:  str           # o que fazer especificamente
    deadline_weeks:  int           # quando completar (semanas a partir de hoje)
    deadline_date:   str           # data absoluta
    business_impact: str           # por que isso importa para o negócio
    pqc_algorithm:   str           # algoritmo PQC recomendado para substituição

@dataclass
class MigrationPlan:
    """Plano de migração completo e priorizado."""
    scan_path:         str
    total_steps:       int
    immediate_steps:   int         # fazer esta semana
    short_term_steps:  int         # fazer em 30 dias
    medium_term_steps: int         # fazer em 90 dias
    long_term_steps:   int         # fazer em 6-12 meses
    total_effort_min:  int         # horas mínimas totais
    total_effort_max:  int         # horas máximas totais
    total_cost_min:    int         # R$ mínimo
    total_cost_max:    int         # R$ máximo
    months_to_deadline: int
    deadline_feasible: bool        # é possível terminar antes do deadline?
    executive_summary: str         # para o CEO/conselho
    steps:             list[MigrationStep]
    generated_at:      str


# Recomendações específicas por categoria
RECOMMENDATIONS = {
    "JWT_NONE":    "Remova imediatamente o suporte a JWT algorithm='none'. Adicione whitelist de algoritmos: ['EdDSA', 'RS256']. Rejeite qualquer token com alg='none'.",
    "HARDCODED":   "Mova segredos para variáveis de ambiente ou cofre (HashiCorp Vault, AWS Secrets Manager). Rotacione qualquer segredo exposto imediatamente.",
    "JWT_RSA":     "Migre assinaturas JWT de RS256/RS384 para EdDSA (Ed25519) como passo intermediário. Target final: ML-DSA-65 (NIST FIPS 204).",
    "JWT_ECDSA":   "Migre assinaturas JWT de ES256/ES384 para EdDSA (Ed25519) como passo intermediário. Target final: ML-DSA-65.",
    "RSA":         "Migre encapsulamento de chave para ML-KEM-768 (NIST FIPS 203) e assinaturas para ML-DSA-65. Use modo híbrido X25519+ML-KEM durante a transição.",
    "ECDSA":       "Migre para Ed25519 como primeiro passo (mantém compatibilidade). Target final: ML-DSA-65 (NIST FIPS 204).",
    "DH":          "Substitua Diffie-Hellman clássico por X25519 imediatamente. Target final: ML-KEM-768 para troca de chaves.",
    "MD5":         "Substitua MD5 por SHA3-256 ou BLAKE2b. Para hashing de senhas: use Argon2id (time_cost=3, memory_cost=65536).",
    "SHA1":        "Substitua SHA-1 por SHA3-256. Para assinaturas: use Ed25519 ou ML-DSA-65.",
    "AES_128":     "Migre para AES-256-GCM. AES-256 oferece 128 bits de segurança quântica contra o algoritmo de Grover.",
    "DES":         "Substitua DES/3DES por AES-256-GCM imediatamente. DES é inseguro mesmo classicamente.",
    "RC4":         "Substitua RC4 por ChaCha20-Poly1305 ou AES-256-GCM imediatamente. RC4 é quebrado.",
    "TLS_LEGACY":  "Desabilite TLS 1.0/1.1. Configure mínimo TLS 1.3. Habilite cipher suites com X25519 e ChaCha20.",
    "WEAK_RANDOM": "Substitua Math.random()/random.random()/java.util.Random por geradores criptograficamente seguros: crypto.getRandomValues(), secrets.token_bytes(32), SecureRandom.",
    "OTHER":       "Revise o uso do algoritmo e consulte NIST SP 800-131A para orientação de migração.",
}

PQC_ALGORITHMS = {
    "RSA":        "ML-KEM-768 (encapsulamento) + ML-DSA-65 (assinaturas) — NIST FIPS 203/204",
    "ECDSA":      "ML-DSA-65 — NIST FIPS 204 (Ed25519 como passo intermediário)",
    "DH":         "ML-KEM-768 — NIST FIPS 203 (X25519 como passo intermediário)",
    "JWT_RSA":    "ML-DSA-65 para assinaturas JWT — NIST FIPS 204",
    "JWT_ECDSA":  "ML-DSA-65 para assinaturas JWT — NIST FIPS 204",
    "JWT_NONE":   "EdDSA (Ed25519) imediato + ML-DSA-65 como target PQC",
    "MD5":        "SHA3-256 ou BLAKE2b (hash) / Argon2id (senhas)",
    "SHA1":       "SHA3-256 — NIST FIPS 202",
    "AES_128":    "AES-256-GCM (resistente a Grover com margem de segurança)",
    "DES":        "AES-256-GCM — NIST FIPS 197",
    "RC4":        "ChaCha20-Poly1305 ou AES-256-GCM",
    "TLS_LEGACY": "TLS 1.3 com X25519Kyber768 (hybrid PQC key exchange)",
    "WEAK_RANDOM":"OS CSPRNG: /dev/urandom, secrets.token_bytes, SecureRandom",
    "HARDCODED":  "HashiCorp Vault / AWS Secrets Manager / Azure Key Vault",
    "OTHER":      "Consultar NIST SP 800-131A Rev 3",
}

BUSINESS_IMPACTS = {
    "JWT_NONE":    "Permite que qualquer atacante forje tokens de autenticação — acesso total sem credenciais.",
    "HARDCODED":   "Credenciais no código-fonte são expostas a qualquer pessoa com acesso ao repositório.",
    "JWT_RSA":     "JWTs poderão ser forjados quando computadores quânticos ficarem disponíveis — comprometendo toda a autenticação.",
    "RSA":         "Dados criptografados hoje poderão ser decifrados retroativamente (Harvest Now, Decrypt Later).",
    "ECDSA":       "Assinaturas digitais e certificados se tornarão inválidos com hardware quântico.",
    "DH":          "Troca de chaves comprometida — sessões TLS poderão ser decifradas retroativamente.",
    "MD5":         "Hashes MD5 podem ser revertidos em segundos — senhas e tokens são vulneráveis.",
    "SHA1":        "SHA-1 foi quebrado em 2017 (ataque SHAttered) — certificados e assinaturas são inseguros.",
    "AES_128":     "AES-128 oferece apenas 64 bits de segurança quântica — insuficiente para dados sensíveis de longo prazo.",
    "DES":         "DES pode ser quebrado em horas com hardware moderno — qualquer dado criptografado está exposto.",
    "RC4":         "RC4 tem fraquezas conhecidas exploráveis — usado em ataques BEAST e RC4NOMORE.",
    "TLS_LEGACY":  "TLS 1.0/1.1 vulneráveis a POODLE, BEAST e outros ataques — comunicação não é segura.",
    "WEAK_RANDOM": "Geração de tokens, senhas e chaves é previsível — atacante pode adivinhar valores gerados.",
    "HARDCODED":   "Segredos no código-fonte ficam permanentemente no histórico git — impossível de apagar completamente.",
    "OTHER":       "Vulnerabilidade criptográfica pode comprometer confidencialidade, integridade ou autenticidade.",
}


def generate_migration_plan(
    findings: list[dict],
    scan_path: str = "",
    hourly_rate_brl: int = DEV_HOUR_COST_BRL,
) -> MigrationPlan:
    """
    Gera plano de migração priorizado por impacto de negócio.

    Args:
        findings: lista de findings do scan
        scan_path: caminho escaneado
        hourly_rate_brl: custo hora dev (padrão R$400)

    Returns:
        MigrationPlan completo e acionável
    """
    if not findings:
        return MigrationPlan(
            scan_path=scan_path, total_steps=0,
            immediate_steps=0, short_term_steps=0,
            medium_term_steps=0, long_term_steps=0,
            total_effort_min=0, total_effort_max=0,
            total_cost_min=0, total_cost_max=0,
            months_to_deadline=_months_to_cnsa(),
            deadline_feasible=True,
            executive_summary="Nenhuma vulnerabilidade criptográfica detectada. Codebase está em conformidade.",
            steps=[],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    # Agrupa findings por categoria
    by_category: dict[str, list[dict]] = {}
    for f in findings:
        cat = RULE_CATEGORY_MAP.get(f.get("rule_id",""), "OTHER")
        by_category.setdefault(cat, []).append(f)

    # Ordena categorias por prioridade de negócio
    sorted_cats = sorted(
        by_category.items(),
        key=lambda x: BUSINESS_PRIORITY.get(x[0], 99)
    )

    steps = []
    total_min = 0
    total_max = 0
    now = datetime.now(timezone.utc)

    for i, (category, cat_findings) in enumerate(sorted_cats, 1):
        effort = REMEDIATION_HOURS.get(category, REMEDIATION_HOURS["OTHER"])
        count  = len(cat_findings)

        # Esforço escala sublinearmente — corrigir 10 ocorrências não é 10x mais trabalho
        scale_factor = 1 + math.log(count, 3) if count > 1 else 1
        hours_min = int(effort["min"] * scale_factor)
        hours_max = int(effort["max"] * scale_factor)
        cost_min  = hours_min * hourly_rate_brl
        cost_max  = hours_max * hourly_rate_brl

        total_min += hours_min
        total_max += hours_max

        # Define deadline com base na prioridade
        biz_prio = BUSINESS_PRIORITY.get(category, 12)
        if biz_prio <= 2:
            priority = "IMMEDIATE"
            deadline_weeks = 1
        elif biz_prio <= 4:
            priority = "SHORT_TERM"
            deadline_weeks = 4
        elif biz_prio <= 7:
            priority = "MEDIUM_TERM"
            deadline_weeks = 12
        else:
            priority = "LONG_TERM"
            deadline_weeks = 26

        deadline_date = (now + timedelta(weeks=deadline_weeks)).strftime("%Y-%m-%d")

        # Arquivos afetados (únicos, máx 5 para não sobrecarregar)
        affected_files = list(set(
            f.get("file","").split("/")[-1]
            for f in cat_findings if f.get("file")
        ))[:5]

        steps.append(MigrationStep(
            step_number=i,
            priority=priority,
            title=f"Migrar {RECOMMENDATIONS.get(category, category)[:60].split('.')[0]}",
            category=category,
            affected_files=affected_files,
            finding_count=count,
            effort_hours_min=hours_min,
            effort_hours_max=hours_max,
            cost_brl_min=cost_min,
            cost_brl_max=cost_max,
            complexity=effort["complexity"],
            recommendation=RECOMMENDATIONS.get(category, "Revisar e substituir por algoritmo PQC recomendado."),
            deadline_weeks=deadline_weeks,
            deadline_date=deadline_date,
            business_impact=BUSINESS_IMPACTS.get(category, "Vulnerabilidade criptográfica."),
            pqc_algorithm=PQC_ALGORITHMS.get(category, "Consultar NIST SP 800-131A"),
        ))

    # Contagem por prioridade
    immediate   = sum(1 for s in steps if s.priority == "IMMEDIATE")
    short_term  = sum(1 for s in steps if s.priority == "SHORT_TERM")
    medium_term = sum(1 for s in steps if s.priority == "MEDIUM_TERM")
    long_term   = sum(1 for s in steps if s.priority == "LONG_TERM")

    months_left    = _months_to_cnsa()
    weeks_left     = months_left * 4
    deadline_feasible = total_max / 40 <= weeks_left  # assume 40h/semana

    executive_summary = _executive_summary(
        steps, total_min, total_max, months_left, deadline_feasible, hourly_rate_brl)

    return MigrationPlan(
        scan_path=scan_path,
        total_steps=len(steps),
        immediate_steps=immediate,
        short_term_steps=short_term,
        medium_term_steps=medium_term,
        long_term_steps=long_term,
        total_effort_min=total_min,
        total_effort_max=total_max,
        total_cost_min=total_min * hourly_rate_brl,
        total_cost_max=total_max * hourly_rate_brl,
        months_to_deadline=months_left,
        deadline_feasible=deadline_feasible,
        executive_summary=executive_summary,
        steps=steps,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def _months_to_cnsa() -> int:
    from datetime import datetime, timezone
    cnsa = datetime(2027, 1, 1, tzinfo=timezone.utc)
    return max(0, int((cnsa - datetime.now(timezone.utc)).days / 30))


def _executive_summary(
    steps: list, min_h: int, max_h: int,
    months: int, feasible: bool, rate: int
) -> str:
    if not steps:
        return "Codebase em conformidade. Nenhuma ação necessária."
    immediate = [s for s in steps if s.priority == "IMMEDIATE"]
    cost_min  = min_h * rate
    cost_max  = max_h * rate
    feasible_str = "dentro do prazo" if feasible else "ATENÇÃO: pode não ser concluído antes do deadline"
    imm_str = (
        f" {len(immediate)} ação(ões) IMEDIATA(S) necessária(s) (esta semana)."
        if immediate else ""
    )
    return (
        f"Plano de migração PQC: {len(steps)} etapa(s), "
        f"esforço estimado {min_h}–{max_h}h de desenvolvimento "
        f"(R${cost_min:,.0f}–R${cost_max:,.0f})."
        f"{imm_str} "
        f"Deadline CNSA 2.0: {months} meses — {feasible_str}."
    )
