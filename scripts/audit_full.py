#!/usr/bin/env python3
"""audit_full.py — Auditoria completa do OmniUil AI.

Versao 3.0 (Out/2026):
- --format json aceita array [] e object {} (antes exigia {)
- /vendor/* procura em server.py E vendor_assessment.py
- QSC-116 verifica em TODOS os YAMLs, nao so pqc-levels.yaml
- .gitignore *.vsix verificado
- Banner do CLI agora sai em stderr (fix commit 3aa6971)
"""

import ast
import re
import os
import subprocess
import json
from pathlib import Path

ROOT = Path.home() / "QSEC"

report = {"critical": [], "warning": [], "ok": []}


def ok(label):
    report["ok"].append(f"[OK]   {label}")


def warn(label):
    report["warning"].append(f"[WARN] {label}")


def crit(label):
    report["critical"].append(f"[ERR]  {label}")


# ════════════════════════════════════════════════════════════════════
# 1. SEGREDOS E VAZAMENTOS
# ════════════════════════════════════════════════════════════════════
print(">>> Verificando segredos e vazamentos...")

gi = (ROOT / ".gitignore").read_text()
for pat in ["*.pem", "private_key", "MANUAL_LICENCA", ".env", "*.db",
            "*.key", "secrets/", "gmail_token", "gmail_credentials",
            "INSTRUCOES_CHAVES", "*.vsix", "agents.db"]:
    (ok if pat in gi else crit)(f".gitignore protege '{pat}'")

# Git history
r = subprocess.run(
    ["git", "log", "--all", "--full-history", "--", "*.pem", "*.key"],
    cwd=ROOT, capture_output=True, text=True
)
(ok if r.stdout.strip() == ""
 else crit)("Chaves privadas nunca commitadas no historico git")

# Tokens hardcoded
token_patterns = [
    r'ghp_[A-Za-z0-9]{36}',
    r'sk-ant-[A-Za-z0-9]{40,}',
    r'gsk_[A-Za-z0-9]{50,}',
    r'AKIA[A-Z0-9]{16}',
]
found_tokens = []
for pyf in ROOT.rglob("*.py"):
    if "__pycache__" in str(pyf):
        continue
    src = pyf.read_text(errors="ignore")
    for pat in token_patterns:
        if re.search(pat, src):
            found_tokens.append(f"{pyf.name}: {pat[:20]}")
(ok if not found_tokens else crit)("Sem tokens hardcoded nos arquivos Python")
for t in found_tokens[:3]:
    crit(f"  Token: {t}")


# ════════════════════════════════════════════════════════════════════
# 2. RUST ENGINE
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando engine Rust...")

rs_files = list((ROOT / "qsec-rust/src").rglob("*.rs"))
total_unwrap = 0
unsafe_files = []
for rsf in rs_files:
    src = rsf.read_text(errors="ignore")
    total_unwrap += src.count(".unwrap()")
    if re.search(r'\bunsafe\b\s*\{', src) and "forbid" not in src:
        unsafe_files.append(rsf.name)

(ok if not unsafe_files else crit)("Sem blocos unsafe nao protegidos")
(ok if total_unwrap < 20 else warn)(f"unwrap() count: {total_unwrap} (ideal < 20)")

for module in ["scanner", "cbom", "x509_discovery", "crypto_graph",
               "taint", "sarif", "config", "error", "rules"]:
    path = ROOT / f"qsec-rust/src/{module}.rs"
    (ok if path.exists() else crit)(f"src/{module}.rs existe")

binary = ROOT / "qsec-rust/target/release/omniuil-ai"
(ok if binary.exists() else crit)("Binario omniuil-ai compilado")


# ════════════════════════════════════════════════════════════════════
# 3. FORMATOS DE SAIDA
# ════════════════════════════════════════════════════════════════════
print(">>> Testando formatos de saida...")

test_file = Path("/tmp/test_audit.py")
test_file.write_text('import hashlib\nhashlib.md5(b"x")\n')

binary_path = "./target/release/omniuil-ai"
if not (ROOT / "qsec-rust/target/release/omniuil-ai").exists():
    binary_path = "./target/release/qsec"

for fmt in ["json", "sarif", "cbom", "x509", "graph"]:
    r3 = subprocess.run(
        [binary_path, "scan", str(test_file), "--format", fmt],
        capture_output=True, text=True, cwd=ROOT / "qsec-rust"
    )
    lines = r3.stdout.split("\n")
    # FIX v3.0: aceita { (object) OU [ (array)
    start = next(
        (i for i, l in enumerate(lines) if l.strip().startswith(("{", "["))),
        None
    )
    valid = False
    if start is not None:
        try:
            json.loads("\n".join(lines[start:]))
            valid = True
        except Exception:
            pass
    (ok if valid else crit)(f"Formato --format {fmt} retorna JSON valido")


# ════════════════════════════════════════════════════════════════════
# 4. PYTHON — ANALISE DE SEGURANCA
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando Python...")

DANGER = [
    (r'eval\s*\(', "eval()"),
    (r'exec\s*\(', "exec()"),
    (r'subprocess.*shell\s*=\s*True', "shell=True"),
    (r'pickle\.loads?\s*\(', "pickle.load"),
    (r'os\.system\s*\(', "os.system()"),
    (r'__import__\s*\(', "__import__ dinamico"),
    (r'yaml\.load\s*\([^,)]+\)', "yaml.load sem Loader"),
]
KNOWN_FP = [
    "dev-secret-change-in-production",
    "_DEFAULT_SECRET",
    "# omniuil:ignore",
    "nosec",
    # Scripts de auditoria podem usar eval/exec em strings
    "scripts/audit",
]

py_files = [
    f for f in ROOT.rglob("*.py")
    if "__pycache__" not in str(f) and "target" not in str(f)
]

syntax_errors = []
danger_found = []
for pyf in py_files:
    src = pyf.read_text(errors="ignore")
    rel = str(pyf).replace(str(ROOT) + "/", "")
    try:
        ast.parse(src)
    except SyntaxError as e:
        syntax_errors.append(f"{rel}:{e.lineno}")
    for pattern, desc in DANGER:
        for i, line in enumerate(src.splitlines(), 1):
            if re.search(pattern, line, re.I) and not line.strip().startswith("#"):
                if not any(fp in line or fp in rel for fp in KNOWN_FP):
                    danger_found.append(f"{rel}:{i} - {desc}")

(ok if not syntax_errors else crit)(f"{len(py_files)} arquivos Python com sintaxe valida")
for e in syntax_errors[:3]:
    crit(f"  Sintaxe: {e}")
(ok if not danger_found else warn)(f"Padroes perigosos Python: {len(danger_found)}")
for d in danger_found[:3]:
    warn(f"  {d}")


# ════════════════════════════════════════════════════════════════════
# 5. API SERVER — ENDPOINTS
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando server.py...")

srv_path = ROOT / "qsec-enterprise/api/server.py"
srv = srv_path.read_text() if srv_path.exists() else ""

# FIX v3.0: incluir vendor_assessment.py na busca
vendor_src = ""
vp = ROOT / "qsec-enterprise/api/vendor_assessment.py"
if vp.exists():
    vendor_src = vp.read_text(errors="ignore")

endpoints = [
    "/license/status", "/license/usage", "/license/activate",
    "/v5/posture", "/v5/drift", "/v5/migration", "/v5/full-analysis",
    "/vendor/questions", "/vendor/assess", "/vendor/report",
    "/scan", "/findings", "/health",
]
for ep in endpoints:
    found = ep in srv or ep in vendor_src
    (ok if found else crit)(f"Endpoint {ep} existe")

security_checks = [
    ("HMAC-SHA3-256 para tokens",   "sha3_256" in srv),
    ("Rate limiting implementado",  "_rate_limit" in srv),
    ("CORS com allowlist",          "CORS_ORIGINS" in srv and '"*"' not in srv),
    ("MAX_FINDINGS anti-OOM",       "MAX_FINDINGS" in srv),
    ("Path traversal protection",   "_safe_api_path" in srv or "safe" in srv.lower()),
    ("Audit log imutavel",          "audit_log" in srv),
    ("Secret default bloqueado",    "QSEC_PRODUCTION" in srv and "_DEFAULT_SECRET" in srv),
    ("repos_tracked no SQLite",     "repos_tracked" in srv),
    ("register_vendor_routes",      "register_vendor_routes" in srv),
    ("Sem wildcard CORS",           'origins="*"' not in srv and "allow_all" not in srv),
]
for label, passed in security_checks:
    (ok if passed else crit)(label)


# ════════════════════════════════════════════════════════════════════
# 6. LICENSING
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando licensing.py...")

lic_path = ROOT / "qsec-enterprise/api/licensing.py"
lic = lic_path.read_text() if lic_path.exists() else ""

lic_checks = [
    ("PLACEHOLDER removido",         "PLACEHOLDER" not in lic),
    ("Chave Ed25519 configurada",    "MCowBQYDK2VwAyEAsg5U31BiVAMiYNV+cK1Ybd6SRWX79K2sTdVu0VnEkME=" in lic),
    ("TIER_LIMITS completo",         all(t in lic for t in ["starter", "pro", "enterprise"])),
    ("get_tier() presente",          "def get_tier" in lic),
    ("check_repo_limit() presente",  "def check_repo_limit" in lic),
    ("issue_license_key() com tier", "def issue_license_key" in lic and "tier" in lic),
    ("check_access() presente",      "def check_access" in lic),
    ("EdDSA em uso (nao RSA)",       "EdDSA" in lic),
    ("Sem instrucoes inline",        "Cole este" not in lic and "Como usar" not in lic),
    ("Chave privada nunca no codigo", "BEGIN PRIVATE" not in lic),
]
for label, passed in lic_checks:
    (ok if passed else crit)(label)


# ════════════════════════════════════════════════════════════════════
# 7. AGENTES
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando agentes...")

agents_dir = ROOT / "agents"
for agent in ["mercury", "vulcan", "dashboard", "demo_agent", "prospecting"]:
    path = agents_dir / f"{agent}.py"
    (ok if path.exists() else crit)(f"agents/{agent}.py existe")
    if path.exists():
        try:
            ast.parse(path.read_text(errors="ignore"))
            ok(f"agents/{agent}.py sintaxe valida")
        except SyntaxError as e:
            crit(f"agents/{agent}.py erro linha {e.lineno}")


# ════════════════════════════════════════════════════════════════════
# 8. V5.0 PILARES
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando v5.0 pilares...")

api_dir = ROOT / "qsec-enterprise/api"
for module in ["quantum_posture", "crypto_drift", "migration_intelligence",
               "vendor_assessment"]:
    path = api_dir / f"{module}.py"
    (ok if path.exists() else crit)(f"{module}.py existe")
    if path.exists():
        try:
            ast.parse(path.read_text())
            ok(f"{module}.py sintaxe valida")
        except SyntaxError as e:
            crit(f"{module}.py erro sintaxe: {e}")

qp_path = api_dir / "quantum_posture.py"
qp = qp_path.read_text() if qp_path.exists() else ""
(ok if "severity_floor" in qp else warn)("quantum_posture: invariante severity_floor")
(ok if "2027" in qp else warn)("quantum_posture: deadline CNSA 2.0")


# ════════════════════════════════════════════════════════════════════
# 9. YAML RULES
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando regras YAML...")

yaml_dir = ROOT / "qsec-rust/.qsec/rules"
total_rules = 0
yaml_issues = []

# FIX v3.0: le TODOS os YAMLs e verifica presenca global
all_yaml_content = ""
for yf in yaml_dir.glob("*.yaml"):
    content = yf.read_text()
    all_yaml_content += content + "\n"
    rules = [l for l in content.split("\n") if l.strip().startswith("- id:")]
    total_rules += len(rules)
    if 'languages: ["*"]' in content:
        yaml_issues.append(f"{yf.name}: languages:[*] invalido")

# Verifica IDs chave em QUALQUER YAML (nao so pqc-levels.yaml)
for rule_id in ["QSC-116", "QSC-200", "QSC-H001", "QSC-H004"]:
    if rule_id not in all_yaml_content:
        yaml_issues.append(f"{rule_id} ausente em TODOS os YAMLs")

(ok if not yaml_issues else crit)(f"{total_rules} regras YAML integras")
for issue in yaml_issues:
    crit(f"  {issue}")
(ok if "HQC" in all_yaml_content else warn)("HQC presente nas regras")
(ok if "FN-DSA" in all_yaml_content or "FALCON" in all_yaml_content.upper()
 else warn)("FN-DSA/FALCON presente nas regras")


# ════════════════════════════════════════════════════════════════════
# 10. CARGO + GIT
# ════════════════════════════════════════════════════════════════════
print(">>> Auditando Cargo.toml e git...")

cargo_path = ROOT / "qsec-rust/Cargo.toml"
cargo = cargo_path.read_text() if cargo_path.exists() else ""
(ok if 'name = "omniuil-ai"' in cargo else crit)("Binario omniuil-ai configurado")
(ok if 'name = "qsec"' in cargo else crit)("Lib qsec sem hifen")
for dep in ["serde", "serde_json", "regex"]:
    (ok if dep in cargo else crit)(f"Dependencia {dep} presente")

r = subprocess.run(
    ["git", "remote", "get-url", "origin"],
    cwd=ROOT, capture_output=True, text=True
)
url = r.stdout.strip()
(ok if "@" not in url else crit)("Remote git sem token na URL")
(ok if "omniuil-ai" in url else crit)("Remote aponta para omniuil-ai")

for f, label in [
    ("SECURITY.md", "SECURITY.md existe"),
    ("scripts/verify-release.sh", "verify-release.sh existe"),
    ("MANUAL_LICENCA.md", "MANUAL_LICENCA.md local"),
]:
    (ok if (ROOT / f).exists() else warn)(label)


# ════════════════════════════════════════════════════════════════════
# RELATORIO FINAL
# ════════════════════════════════════════════════════════════════════
n_ok = len(report["ok"])
n_warn = len(report["warning"])
n_crit = len(report["critical"])
total = n_ok + n_warn + n_crit
score = int(n_ok / max(total, 1) * 100)

print()
print("=" * 65)
print("  AUDITORIA COMPLETA - OmniUil AI v3.0")
print("=" * 65)
print(f"\n  PASSOU    : {n_ok}/{total} verificacoes")
print(f"  AVISOS    : {n_warn}")
print(f"  CRITICOS  : {n_crit}")
print(f"\n  SCORE     : {score}/100")

if n_crit == 0 and n_warn <= 3:
    print("\n  APROVADO PARA LANCAMENTO")
elif n_crit == 0:
    print("\n  SEM CRITICOS - Pronto com ressalvas menores")
else:
    print("\n  RESOLVER CRITICOS antes do lancamento")

if report["critical"]:
    print("\n-- CRITICOS " + "-" * 52)
    for i in report["critical"]:
        print(f"  {i}")

if report["warning"]:
    print("\n-- AVISOS " + "-" * 54)
    for i in report["warning"]:
        print(f"  {i}")

print("\n-- OK (primeiras 30) " + "-" * 43)
for i in report["ok"][:30]:
    print(f"  {i}")
if len(report["ok"]) > 30:
    print(f"  ... e mais {len(report['ok']) - 30} verificacoes OK")

print(f"\n{'=' * 65}")
print(f"  Total: {total} verificacoes | Score: {score}/100")
print(f"{'=' * 65}")
