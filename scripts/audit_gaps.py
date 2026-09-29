#!/usr/bin/env python3
"""audit_gaps.py — Auditoria de segurança dos 3 GAPs.

Versao 2.0 (Set/2026):
- Detecta blocos unsafe REAIS via regex (nao apenas a palavra)
- Atualizado para estado pos-correcao (QSC-H004 existe, HQC e FN-DSA corretos)
- Adiciona check de severidade H004 (deve ser LOW/INFO)
- Verifica se testes existem no disco
"""

import ast
import re
from pathlib import Path

ROOT = Path.home() / "QSEC"

issues = []
warnings = []
ok = []


def check(label, passed, detail=""):
    if passed:
        ok.append(f"[OK]   {label}")
    else:
        issues.append(f"[ERR]  {label}{': ' + detail if detail else ''}")


def warn(label, detail=""):
    warnings.append(f"[WARN] {label}{': ' + detail if detail else ''}")


def reset():
    global issues, warnings, ok
    result = (len(ok), len(warnings), len(issues))
    issues = []
    warnings = []
    ok = []
    return result


def header(title):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def dump():
    for item in ok:
        print(f"  {item}")
    for item in warnings:
        print(f"  {item}")
    for item in issues:
        print(f"  {item}")


# ============================================================
# 1 — vendor_assessment.py
# ============================================================
header("AUDITORIA 1 - vendor_assessment.py")

va_path = ROOT / "qsec-enterprise/api/vendor_assessment.py"
va = va_path.read_text(encoding="utf-8", errors="replace")

try:
    ast.parse(va)
    check("Sintaxe Python valida", True)
except SyntaxError as e:
    check("Sintaxe Python valida", False, str(e))

check("Sem eval()", "eval(" not in va)
check("Sem exec()", "exec(" not in va)
check("Sem shell=True", "shell=True" not in va)
check("Sem pickle", "import pickle" not in va)
check("Sem subprocess", "import subprocess" not in va)
check("Sem I/O de rede",
      all(x not in va for x in ["requests.", "import urllib", "import httpx", "import socket"]))

q_ids = re.findall(r'"id"\s*:\s*"(Q\d+)"', va)
check(f"10 perguntas (encontradas: {len(q_ids)})", len(q_ids) >= 10)
check("RESPONSE_SCORES definido", "RESPONSE_SCORES" in va)
check("calculate_vendor_score() definida", "def calculate_vendor_score" in va)
check("create_assessment() definida", "def create_assessment" in va)
check("assessment_to_report() definida", "def assessment_to_report" in va)
check("register_vendor_routes() definida", "def register_vendor_routes" in va)
check("Score 0-100 calculado", "earned_points" in va and "total_weight" in va)
check("CNSA2 score separado", "cnsa2_score" in va)
check("assessment_id usa SHA-256", "hashlib.sha256" in va)

if "[100, 66, 33, 0]" in va:
    check("Escala de pontuacao [100,66,33,0]", True)
else:
    warn("Escala [100,66,33,0] nao encontrada literalmente")

if "Authorization" not in va and "token" not in va.lower():
    warn("Endpoints vendor sem auth propria - depende do server.py")
else:
    check("Endpoints vendor verificam auth", True)

dump()
va_ok, va_warn, va_err = reset()


# ============================================================
# 2 — cbom.rs
# ============================================================
header("AUDITORIA 2 - cbom.rs")

cbom = (ROOT / "qsec-rust/src/cbom.rs").read_text(encoding="utf-8", errors="replace")

# Blocos unsafe REAIS (regex)
has_unsafe_block = bool(re.search(r'\bunsafe\s*\{', cbom))
has_directive = "#![forbid(unsafe_code)]" in cbom or "#![deny(unsafe_code)]" in cbom

if has_unsafe_block:
    linhas = []
    for m in re.finditer(r'\bunsafe\s*\{', cbom):
        linhas.append(cbom[:m.start()].count("\n") + 1)
    check("Sem blocos unsafe reais", False, f"linhas: {linhas}")
elif has_directive:
    check("Sem blocos unsafe + diretiva declarada", True)
else:
    warn("Sem blocos unsafe, mas sem #![forbid(unsafe_code)]")

check("Sem I/O de rede",
      all(x not in cbom for x in ["std::net", "reqwest", "hyper", "tokio::net"]))

unwrap_count = cbom.count(".unwrap()")
if unwrap_count == 0:
    check("Sem unwrap() no codigo", True)
elif unwrap_count <= 3:
    warn(f"{unwrap_count} unwrap() - verificar seguranca")
else:
    check(f"Poucos unwrap() (encontrados: {unwrap_count})", False)

check("generate_cbom() publica", "pub fn generate_cbom" in cbom)
check("cbom_to_json() publica", "pub fn cbom_to_json" in cbom)
check("cbom_to_cyclonedx() publica", "pub fn cbom_to_cyclonedx" in cbom)
check("CryptoMaturity enum", "CryptoMaturity" in cbom)
check("QuantumRisk enum", "QuantumRisk" in cbom)
check("CbomCompliance struct", "CbomCompliance" in cbom)
check("CNSA2_APPROVED list", "CNSA2_APPROVED" in cbom)
check("QUANTUM_VULNERABLE list", "QUANTUM_VULNERABLE" in cbom)
check("EO-14412 referenciado", "EO-14412" in cbom)
check("Serde Serialize/Deserialize", "Serialize" in cbom and "Deserialize" in cbom)

if "format_timestamp" in cbom and "chrono" not in cbom:
    warn("format_timestamp() sem chrono - aproximacao manual")

for pattern in ["sk-ant", "ghp_", "Bearer ", "api_key =", "AIza"]:
    check(f"Sem token '{pattern[:8]}'", pattern not in cbom)

dump()
cbom_ok, cbom_warn, cbom_err = reset()


# ============================================================
# 3 — pqc-levels.yaml
# ============================================================
header("AUDITORIA 3 - pqc-levels.yaml")

yaml_content = (ROOT / "qsec-rust/.qsec/rules/pqc-levels.yaml").read_text(
    encoding="utf-8", errors="replace")

rules = re.findall(r'^\s*-\s*id:\s*(\S+)', yaml_content, re.MULTILINE)
check(f"Total de regras >= 10 (encontradas: {len(rules)})", len(rules) >= 10)

for rule_id in ["QSC-H001", "QSC-H002", "QSC-H003", "QSC-H004"]:
    check(f"{rule_id} presente", rule_id in yaml_content)

if "QSC-H004" in yaml_content:
    h004 = yaml_content.split("QSC-H004", 1)[1][:500]
    check("QSC-H004 severity LOW ou INFO",
          "severity: LOW" in h004 or "severity: INFO" in h004)

if "HQC" in yaml_content:
    hqc_ok = any(k in yaml_content for k in [
        "FIPS pendente", "nao finalizado", "previsto 2027", "mar/2025",
        "selecionado NIST"
    ])
    check("HQC com status FIPS pendente", hqc_ok)

if "FN-DSA" in yaml_content or "FALCON" in yaml_content:
    fndsa_ok = any(k in yaml_content for k in [
        "FIPS 206", "em desenvolvimento", "nao finalizado"
    ])
    check("FN-DSA com status FIPS 206", fndsa_ok)

check("ML-KEM referenciado (FIPS 203)", "FIPS 203" in yaml_content)
check("ML-DSA referenciado (FIPS 204)", "FIPS 204" in yaml_content)
check("SLH-DSA referenciado (FIPS 205)", "FIPS 205" in yaml_content)
check("Sem languages:[*] invalido", 'languages: ["*"]' not in yaml_content)

if "(?P<" in yaml_content:
    warn("Named capture groups - verificar compatibilidade com regex Rust")

dump()
yaml_ok, yaml_warn, yaml_err = reset()


# ============================================================
# 4 — quantum_posture.py
# ============================================================
header("AUDITORIA 4 - quantum_posture.py")

qp = (ROOT / "qsec-enterprise/api/quantum_posture.py").read_text(
    encoding="utf-8", errors="replace")

try:
    ast.parse(qp)
    check("Sintaxe Python valida", True)
except SyntaxError as e:
    check("Sintaxe Python valida", False, str(e))

check("Invariante 1: severity_floor", "severity_floor" in qp)
check("Invariante 2: risk_color derivado", "risk_color" in qp)
check("Invariante 3: recommendation derivada",
      "_generate_recommendation" in qp and "risk_level" in qp)
# Score limitado a [0,100] por qualquer meio: max/min, clamp, min aninhado
_score_limited = (
    ("max(0" in qp and "100" in qp) or
    ("clamp(0, 100)" in qp) or
    ("clamp(0.0, 100.0)" in qp) or
    ("min(total_penalty, 100)" in qp)
)
check("Score 0-100 limitado", _score_limited)
check("CNSA_DEADLINE definido", "CNSA_DEADLINE" in qp or "2027" in qp)
check("Sem I/O de rede",
      all(x not in qp for x in ["requests.", "import urllib", "import socket"]))
check("Sem eval()/exec()", "eval(" not in qp and "exec(" not in qp)

test1 = ROOT / "qsec-enterprise/api/tests/test_quantum_posture_invariant.py"
test2 = ROOT / "qsec-enterprise/api/tests/test_recommendation_coherence.py"
check("Testes de invariante existem", test1.exists())
check("Testes de coerencia narrativa existem", test2.exists())

dump()
qp_ok, qp_warn, qp_err = reset()


# ============================================================
# RELATORIO FINAL
# ============================================================
total_ok = va_ok + cbom_ok + yaml_ok + qp_ok
total_warn = va_warn + cbom_warn + yaml_warn + qp_warn
total_err = va_err + cbom_err + yaml_err + qp_err
total = total_ok + total_warn + total_err
score = int(total_ok / max(total, 1) * 100)

print()
print("=" * 60)
print("  RELATORIO FINAL DE AUDITORIA - 3 GAPs")
print("=" * 60)
print()
print(f"  OK:        {total_ok}")
print(f"  Avisos:    {total_warn}")
print(f"  Criticos:  {total_err}")
print()
print(f"  Score:     {score}/100")

if total_err == 0 and total_warn <= 3:
    print()
    print("  APROVADO - Pronto para fusao")
elif total_err == 0:
    print()
    print("  SEM CRITICOS - Revisar avisos")
else:
    print()
    print("  RESOLVER CRITICOS antes da fusao")

print()
print("-- Por componente ---------------------------------------")
print(f"  vendor_assessment.py : {va_ok} OK, {va_warn} avisos, {va_err} criticos")
print(f"  cbom.rs              : {cbom_ok} OK, {cbom_warn} avisos, {cbom_err} criticos")
print(f"  pqc-levels.yaml      : {yaml_ok} OK, {yaml_warn} avisos, {yaml_err} criticos")
print(f"  quantum_posture.py   : {qp_ok} OK, {qp_warn} avisos, {qp_err} criticos")
