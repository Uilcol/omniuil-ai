# QSEC Enterprise v3.0.0
## Post-Quantum Cryptographic Firewall

[![CI](https://github.com/yourorg/qsec/actions/workflows/ci.yml/badge.svg)](...)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS_203%2F204-green)](https://csrc.nist.gov/pubs/fips/203/final)

---

## O que é o QSEC

QSEC é uma plataforma autônoma de segurança pós-quântica com dois layers:

| Layer | Tecnologia | Função |
|-------|-----------|--------|
| Engine | Rust + liboqs | Scan, PQC crypto, SBOM, JWT, CLI |
| Agentes | Python + Claude API | Auditoria IA, remediação autônoma, resposta a incidentes |
| API | Flask REST + SSE | Interface para CI/CD, dashboards, SDKs |
| Dashboard | HTML/JS | Interface web em tempo real |

### Algoritmos NIST FIPS 203/204
- **KEM**: X25519 + ML-KEM-1024 (proteção HNDL)
- **DSA**: Ed25519 + ML-DSA-87
- **Symmetric**: AES-256-GCM
- **KDF**: HKDF-SHA3-256 com salt domain-specific

---

## Instalação Rápida

### Docker (recomendado — inclui liboqs real)

```bash
git clone https://github.com/yourorg/qsec.git
cd qsec

# Configurar secrets
cp .env.example .env
# Editar QSEC_API_SECRET e ANTHROPIC_API_KEY

# Build + start (compila liboqs automaticamente)
docker compose -f qsec-enterprise/docker/docker-compose.yml up -d

# Verificar
curl http://localhost:8080/health
# → {"status":"ok","engine":"production","version":"3.0.0"}
```

### Manual — Engine Rust

```bash
# Dependências (Ubuntu/Debian)
sudo apt-get install build-essential cmake ninja-build libssl-dev pkg-config

# Build liboqs (ML-KEM-1024 + ML-DSA-87 reais)
git clone --depth 1 --branch 0.11.0 \
  https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build \
  -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DOQS_ALGS_ENABLED="ML_KEM_1024;ML_DSA_87"
sudo cmake --build /tmp/liboqs/build --parallel
sudo cmake --install /tmp/liboqs/build
sudo ldconfig

# Build qsec com PQC real
cd qsec-rust
OQS_DIR=/usr/local cargo build --release --features liboqs

# Instalar
sudo cp target/release/qsec /usr/local/bin/
qsec info  # deve mostrar: nist_pqc_compliant: true
```

### Manual — API + Agentes

```bash
cd qsec-agents
pip install -r requirements.txt flask==3.1.2 gunicorn

export QSEC_API_SECRET="your-secret"
export QSEC_BIN="/usr/local/bin/qsec"
export ANTHROPIC_API_KEY="sk-ant-..."

# Desenvolvimento
python qsec-enterprise/api/server.py

# Produção (4 workers)
gunicorn --bind 0.0.0.0:8080 --workers 4 --threads 4 \
  "qsec-enterprise.api.server:app"
```

---

## Uso — CLI

```bash
# ── Engine Rust ──────────────────────────────────────────────────────────────

# Scan de criptografia fraca
qsec scan ./src --format json --fail-on-critical

# Assinar artefato (ML-DSA-87 + Ed25519)
qsec sign ./dist/app --out app.qsec.json

# Verificar assinatura
qsec verify ./dist/app --manifest app.qsec.json

# SBOM CycloneDX 1.5
qsec sbom . --out sbom.cyclonedx.json

# PQC-JWT
qsec token issue --subject user@corp.com --ttl 3600 --audience api.internal
qsec token verify --token <jwt> --audience api.internal
qsec token revoke --jti <jti>

# Chaves
qsec keys status
qsec keys rotate
qsec keys revoke --key-id <kid>

# API Keys
qsec apikey create --name ci-bot --scope read,write --ttl-days 90
qsec apikey verify --key qsec_<64hex> --scope read
qsec apikey list

# Pipeline completo (scan + sbom + sign + attest)
qsec pipeline . --artifacts dist/app --out-dir ./qsec-out

# ── Agentes Python (IA) ───────────────────────────────────────────────────────

# Auditoria completa com IA + auto-remediação
python qsec-agents/main.py audit ./src --auto-remediate

# Monitoramento contínuo
python qsec-agents/main.py monitor ./src --interval 30

# Resposta a incidente
python qsec-agents/main.py incident key_compromise \
  --desc "RSA private key exposed in GitHub commit"
```

---

## Uso — API REST

```bash
# 1. Autenticar
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my-app","client_secret":"your-secret"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# 2. Scan (inicia job em background)
JOB=$(curl -s -X POST http://localhost:8080/api/v1/agents/audit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path":"./src","auto_remediate":true}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['job_id'])")

# 3. Aguardar resultado
curl -s http://localhost:8080/api/v1/agents/audit/$JOB \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# 4. Emitir PQC-JWT
curl -s -X POST http://localhost:8080/api/v1/jwt/issue \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subject":"user@corp.com","audience":"api.internal","ttl":3600}'

# 5. Dashboard
curl -s http://localhost:8080/api/v1/dashboard \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Uso — Python SDK

```python
from qsec_sdk import QsecClient

client = QsecClient(
    base_url="http://localhost:8080",
    client_secret="your-secret",
)

# Auditoria completa com espera
result = client.scan.run("./src", auto_remediate=True)
print(f"QRS: {result.quantum_risk_score}/100 ({result.risk_label})")
print(f"Critical: {result.critical_count}")

# Falhar CI se houver críticos
if result.critical_count > 0:
    raise SystemExit(1)

# PQC-JWT
token = client.jwt.issue("user@corp.com", audience="api.internal")
claims = client.jwt.verify(token, audience="api.internal")

# Rotação de chaves
key_status = client.keys.status()
if key_status.is_expiring_soon:
    client.keys.rotate(reason="Automated rotation — expiry < 7 days")

# SBOM
sbom = client.sbom.generate(".")

# Verificar engine
info = client.engine.info()
print(f"Production PQC: {info.is_production}")
```

### SDK no CI/CD (GitHub Actions)

```yaml
- name: QSEC Security Scan
  run: |
    python -m qsec_sdk scan ./src \
      --url http://qsec-api:8080 \
      --secret ${{ secrets.QSEC_SECRET }} \
      --fail-on critical \
      --auto-remediate
```

---

## Integração CI/CD Nativa

O arquivo `.github/workflows/ci.yml` inclui:

1. **Rust engine CI** — `cargo test` + clippy + fmt
2. **liboqs build** — ML-KEM + ML-DSA reais em cada PR
3. **Python agents CI** — pytest + flake8 + path traversal verify
4. **QSEC self-scan** — o projeto escaneia a si mesmo em cada build
5. **SBOM automático** — CycloneDX gerado e publicado em cada build
6. **Docker build** — imagem construída e pushed para GHCR em cada merge

---

## Segurança

### Garantias em produção

| Propriedade | Implementação |
|------------|--------------|
| Zero unsafe code | `#![forbid(unsafe_code)]` no Rust |
| Zeroize on Drop | `ZeroizeOnDrop` em todas as structs com chave privada |
| Timing-safe | `subtle::ConstantTimeEq` em todas as comparações de segredos |
| HKDF salt | Salt domain-specific `"qsec-hkdf-salt-v3-kem-key-derivation"` |
| AES-256-GCM key | `okm.zeroize()` após derivação HKDF |
| Nonce validation | `ct.nonce.len() != 12` validado antes de `from_slice` |
| JWT clock skew | 30s (não 60s) — minimize replay attack window |
| JWT revocation | Antes da verificação de expiração (timing oracle prevention) |
| Path traversal | `_safe_path()` + `Path.resolve()` + blocklist em todos os agents |
| API auth | HMAC `compare_digest` — timing-safe secret comparison |
| Key entropy | 128-bit key IDs (16 bytes) |
| Log rotation | Alert log rotado em 5 MB |
| Token budget | `MAX_TOTAL_TOKENS=80000` — guarda contra runaway agent loops |
| Production gate | `QSEC_PRODUCTION=1` bloqueia modo simulação |

### Auditoria de segurança

24 vulnerabilidades identificadas e corrigidas na auditoria de março 2026. Ver `SECURITY_AUDIT.md`.

---

## Roadmap

- [ ] Interface web com autenticação
- [ ] Suporte a múltiplas keyspaces por tenant
- [ ] Integração GitLab CI nativa
- [ ] Scanner de containers (Docker images)
- [ ] API de webhooks (Slack, PagerDuty)
- [ ] Exportação para Splunk / Elastic SIEM
- [ ] SDK Java + Go

---

## Licença

MIT — ver [LICENSE](LICENSE)

---

*QSEC v3.0.0 — Infraestrutura de Confiança Criptográfica para a Era Quântica*
