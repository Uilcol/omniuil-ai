# OmniUil AI — Post-Quantum Cryptographic Security Platform

<div align="center">

![OmniUil AI](https://img.shields.io/badge/OmniUil_AI-v3.3.0-00d4ff?style=for-the-badge&logoColor=white)
![Status](https://img.shields.io/badge/Status-Online-00e676?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-1.75+-CE422B?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![NIST](https://img.shields.io/badge/NIST-FIPS_203%2F204-1a3a5c?style=for-the-badge)

**O único scanner de segurança criptográfica pós-quântica com taint analysis,
IA local e dashboard empresarial — 100% na sua infraestrutura, sem enviar
código para fora da sua máquina.**

[🚀 Instalação](#instalação) • [🎯 O que detecta](#o-que-detecta) • [📊 Casos de uso reais](#casos-de-uso-reais) • [💼 Planos](#planos)

</div>

---

## O Problema

Em 2030, computadores quânticos serão capazes de quebrar **RSA**, **ECDSA**
e **Diffie-Hellman** — os algoritmos que protegem 99% das comunicações da
internet hoje.

O ataque _"Harvest Now, Decrypt Later"_ (HNDL) já está acontecendo: dados
criptografados hoje podem ser capturados e decifrados quando o hardware quântico
estiver disponível. O NIST publicou os primeiros padrões PQC em 2024 (FIPS 203/204).
A conformidade com **CNSA 2.0** torna-se obrigatória em **2027**.

---

## O que detecta

### 14 regras PQC builtin

| Regra | Severidade | Detecta |
|-------|-----------|---------|
| QSC-001 | CRITICAL | RSA em qualquer forma |
| QSC-002 | CRITICAL | ECDSA / ECDH / curvas elípticas |
| QSC-003 | CRITICAL | Diffie-Hellman clássico |
| QSC-010 | HIGH | MD5 |
| QSC-011 | HIGH | SHA-1 |
| QSC-012 | HIGH | AES modo ECB |
| QSC-013 | HIGH | DES / 3DES |
| QSC-014 | CRITICAL | RC4 |
| QSC-020 | CRITICAL | JWT algorithm "none" |
| QSC-021 | MEDIUM | JWT HMAC simétrico |
| QSC-022 | CRITICAL | JWT assinado com RSA |
| QSC-030 | HIGH | Segredos hardcoded |
| QSC-031 | HIGH | Semente aleatória previsível |
| QSC-116 | CRITICAL | Chave privada PEM embutida no código |

### Language Adapters (APIs nativas por linguagem)

| Linguagem | APIs detectadas |
|-----------|----------------|
| Python | PyCryptodome, hashlib, passlib, Flask-JWT |
| Java | JCE, Bouncy Castle, Spring Security, JSSE |
| C# | System.Security.Cryptography, BouncyCastle .NET |
| Go | crypto/rsa, crypto/ecdsa, crypto/md5, x/crypto |
| JavaScript/TypeScript | Node.js crypto, jsonwebtoken, CryptoJS |

### Taint Analysis

Rastreia dados externos (HTTP requests, variáveis de ambiente) até operações
criptográficas — detecta ataques de injeção de parâmetros como Algorithm
Injection em JWT:

```python
# DETECTADO AUTOMATICAMENTE:
algoritmo = request.json.get("alg")           # ← fonte: HTTP
token = jwt.encode(data, key, algorithm=algoritmo)  # ← sink: JWT
# ALERTA: atacante envia {"alg":"none"} → bypass total de autenticação
```

### Regras YAML customizáveis

Adicione regras específicas da sua organização sem recompilar:

```yaml
rules:
  - id: "CUSTOM-001"
    severity: "CRITICAL"
    title: "API legada insegura"
    pattern: "api_v1_legacy\\("
    languages: ["python", "java"]
```

---

## Casos de Uso Reais

### OWASP WebGoat
```
Scanner findings  : 51
CRITICAL          : 13
HIGH              : 38
```
Incluindo: JWT `alg:none`, RSA-2048, MD5 em senhas, segredos hardcoded.

### Keycloak (projeto enterprise real)
```
Scanner findings  : 443
CRITICAL          : 382
HIGH              : 50
```
RSA como provider padrão em `DefaultKeyProviders` — mapeamento completo
para plano de migração PQC.

### Spring Security
```
Scanner findings  : 437
CRITICAL          : 393
HIGH              : 44
```

> Detalhes completos em [CASE_STUDY.md](./CASE_STUDY.md)

---

## Instalação

### Pré-requisitos

- Docker Desktop
- Rust / Cargo (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Linux, macOS ou WSL2

### 1 comando

```bash
git clone https://github.com/Uilcol/omniuil-ai.git
cd omniuil-ai/qsec-enterprise
bash install.sh
```

Dashboard disponível em `http://localhost:8080`

### CLI (engine independente)

```bash
cd omniuil-ai/qsec-rust
cargo build --release

# Escanear projeto
./target/release/qsec scan ./meu-projeto --format text

# Excluir diretórios específicos
./target/release/qsec scan ./meu-projeto --exclude "**/mock/**,**/generated/**"

# Saída JSON para CI/CD
./target/release/qsec scan ./meu-projeto --format json

# SARIF para GitHub Code Scanning
./target/release/qsec scan ./meu-projeto --format sarif
```

---

## Formatos de Saída

| Formato | Comando | Uso |
|---------|---------|-----|
| Texto | `--format text` | Terminal, leitura humana |
| JSON | `--format json` | Integração, CI/CD, automação |
| SARIF 2.1.0 | `--format sarif` | GitHub Security tab, Azure DevOps |

---

## API REST (22 endpoints)

```bash
# Autenticar
POST /api/v1/auth/token

# Scan assíncrono
POST /api/v1/scan
GET  /api/v1/scan/{job_id}

# Auditoria completa com agentes IA
POST /api/v1/audit
GET  /api/v1/audit/{job_id}

# Licença
GET  /api/v1/license/status
GET  /api/v1/license/usage
POST /api/v1/license/activate

# SBOM CycloneDX 1.5
POST /api/v1/sbom

# PQC-JWT
POST /api/v1/jwt/issue
POST /api/v1/jwt/verify
POST /api/v1/jwt/revoke

# Chaves
GET  /api/v1/keys/status
POST /api/v1/keys/rotate

# Dashboard
GET  /api/v1/dashboard
GET  /api/v1/health
```

---

## Integração CI/CD

### GitHub Actions

```yaml
- name: OmniUil AI Security Scan
  run: |
    ./target/release/qsec scan ./src --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Agentes IA (Ollama local — sem API key)

5 agentes autônomos que rodam 100% na sua infraestrutura:

| Agente | Função |
|--------|--------|
| ScannerAgent | Escaneia projetos autonomamente |
| AnalysisAgent | Calcula Quantum Risk Score (0-100) |
| RemediationAgent | Sugere correções específicas por vulnerabilidade |
| MonitoringAgent | Monitora regressões em tempo real |
| IncidentAgent | Responde alertas críticos automaticamente |

Os agentes disponíveis variam conforme o plano contratado.

---

## Planos

| | **Free** | **Starter** | **Pro** | **Enterprise** |
|---|---|---|---|---|
| Engine CLI (`qsec-rust`) | ✅ Ilimitado | ✅ Ilimitado | ✅ Ilimitado | ✅ Ilimitado |
| 14 regras PQC + YAML custom | ✅ | ✅ | ✅ | ✅ |
| Taint analysis | ✅ | ✅ | ✅ | ✅ |
| SBOM, PQC-JWT, SARIF | ✅ | ✅ | ✅ | ✅ |
| Dashboard web | ❌ | ✅ | ✅ | ✅ |
| Repositórios monitorados | — | Até 5 | Ilimitado | Ilimitado |
| API REST | ❌ | ✅ | ✅ | ✅ |
| Agentes IA ativos | ❌ | Scanner + Analysis | Todos os 5 | Todos os 5 |
| Auto-remediate via LLM | ❌ | ❌ | ✅ | ✅ |
| Usuários no dashboard | — | 1 | Até 5 | Ilimitado |
| Integrações (Slack, Jira) | ❌ | ❌ | ✅ | ✅ |
| Relatório de conformidade CNSA 2.0 | ❌ | ❌ | ✅ | ✅ |
| Suporte | Comunidade | E-mail | E-mail prioritário | Canal dedicado + SLA |
| Deploy | Self-hosted | Self-hosted | Self-hosted | Self-hosted assistido |

### Solicitar licença ou demonstração

📋 **[Preencher formulário de contato →](https://docs.google.com/forms/d/e/1FAIpQLSfNMleQF2Ik-jHTT5HgPdsdkirXc4U_eJV3ON2hzI8ZR1TmQg/viewform?usp=header)**

Respondemos em até 1 dia útil com proposta ou agenda de demonstração técnica.

---

## Arquitetura

```
OmniUil AI
├── qsec-rust/          Engine de análise (Rust, Apache 2.0)
│   ├── 14 regras PQC builtin
│   ├── Taint analysis (fonte → sink)
│   ├── Language adapters (5 linguagens)
│   ├── YAML Rule Engine
│   ├── Evidence Graph
│   └── SBOM / PQC-JWT / SARIF
│
├── qsec-agents/        Agentes IA (Python, Licença Comercial)
│   ├── ScannerAgent
│   ├── AnalysisAgent
│   ├── RemediationAgent
│   ├── MonitoringAgent
│   └── IncidentAgent (Ollama local)
│
└── qsec-enterprise/    API + Dashboard (Python, Licença Comercial)
    ├── API REST 22 endpoints
    ├── Dashboard Web
    ├── Sistema de licenciamento (JWT Ed25519)
    ├── Controle de tiers por chave
    ├── SQLite + Docker
    └── Rate limiting + Audit log imutável
```

---


## OmniUil AI v5.0 — Tres Pilares Estrategicos

### Pilar 1 — Quantum Posture Score
Score determinístico 0-100. Responde em 60 segundos: qual e sua exposicao ao risco quantico?
Calculado deterministicamente — auditavel perante conselho, auditores e reguladores (BACEN, ANPD, TCU).

### Pilar 2 — Crypto Drift Detection
Detecta regressoes criptograficas entre scans consecutivos.
Dev faz merge de PR com RSA: alerta em 30 minutos. Score caiu: alerta para CISO.

### Pilar 3 — Migration Intelligence
Transforma 443 findings numa lista paralisante em plano acionavel.
Priorizado por impacto de negocio. Estimativa de custo em BRL e deadline CNSA 2.0.

Endpoints: POST /api/v1/v5/full-analysis | /v5/posture | /v5/drift | /v5/migration

## Licenciamento

| Componente | Licença |
|---|---|
| `qsec-rust` (engine/CLI) | Apache 2.0 — livre para qualquer uso |
| `qsec-enterprise` + `qsec-agents` | Licença comercial — ver [qsec-enterprise/LICENSE](./qsec-enterprise/LICENSE) |

Detalhes em [LICENSE_SUMMARY.md](./LICENSE_SUMMARY.md).

---

## Conformidade

| Padrão | Status |
|--------|--------|
| NIST FIPS 203 (ML-KEM) | ✅ Implementado (modo referência) |
| NIST FIPS 204 (ML-DSA) | ✅ Implementado (modo referência) |
| CNSA 2.0 (obrigatório 2027) | ✅ Checklist completo |
| CycloneDX 1.5 (SBOM) | ✅ Implementado |
| SARIF 2.1.0 | ✅ GitHub Code Scanning |
| LGPD / ANPD Brasil | ✅ Dados locais, sem cloud |

---

## Desenvolvido no Brasil 🇧🇷 · 2026

**Repositório:** [github.com/Uilcol/omniuil-ai](https://github.com/Uilcol/omniuil-ai)
