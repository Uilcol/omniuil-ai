# OmniUil AI — Post-Quantum Cryptographic Firewall

<div align="center">

![OmniUil AI](https://img.shields.io/badge/OmniUil AI-v3.3.0-0A2540?style=for-the-badge&logo=shield&logoColor=3B82F6)
![Rust](https://img.shields.io/badge/Rust-1.75+-CE422B?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-10B981?style=for-the-badge)
![NIST](https://img.shields.io/badge/NIST-FIPS%20203%2F204-1D4ED8?style=for-the-badge)

**O único firewall criptográfico com IA local que detecta, analisa e corrige vulnerabilidades quânticas no seu código — sem enviar nada para fora da sua máquina.**

[🚀 Instalação](#instalação-em-1-comando) • [🎯 Como Funciona](#como-funciona) • [📊 Demo](#demo) • [🔬 Arquitetura](#arquitetura)

</div>

---

## O Problema

Em 2030, computadores quânticos serão capazes de quebrar **RSA**, **ECDSA** e **ECDH** — os algoritmos que protegem 99% das comunicações da internet hoje.

Dados criptografados **agora** podem ser capturados e decifrados **depois** — o ataque _"Harvest Now, Decrypt Later"_ (HNDL) já está acontecendo.

O NIST publicou os primeiros padrões PQC em 2024. A conformidade com **CNSA 2.0** torna-se obrigatória em **2027**.

```
Você tem:  RSA-2048        →  ❌ Quebrável pelo algoritmo de Shor
Você quer: ML-KEM-1024     →  ✅ Seguro contra ameaças quânticas (NIST FIPS 203)
           ML-DSA-87       →  ✅ Assinaturas pós-quânticas (NIST FIPS 204)
```

---

## O que o OmniUil AI faz

```
$ omniuil-ai scan ./meu-projeto --format text

[OmniUil AI v3.3.0] Backend: reference
╔══════════════════════════════════════════════════════════════╗
║         OmniUil AI — Relatório de Análise Criptográfica  v3.3      ║
╚══════════════════════════════════════════════════════════════╝
  Scanner findings  : 7
  Taint findings    : 4
  CRITICAL          : 3
  HIGH              : 4

── CRITICAL ──────────────────────────────────────────────────
  [QSC-001] RSA detectado
  📍 src/auth.py:19
  📝 RSA é vulnerável ao algoritmo de Shor.
  ✅ Migre para ML-DSA (assinaturas) ou ML-KEM (troca de chaves).
  🔍 chave_rsa = RSA.generate(2048)

── TAINT ANALYSIS ────────────────────────────────────────────
  [TAINT-001] Fluxo de taint: requisição HTTP → sink criptográfico
  🔀 'algoritmo' (HTTP request) linha 26 → jwt.encode() linha 27
  📝 Atacante pode injetar algorithm="none" e desabilitar verificação JWT.
```

---

## Funcionalidades

### Scanner PQC (14 regras)
| Regra | Severidade | Detecta |
|-------|-----------|---------|
| QSC-001 | CRITICAL | RSA — vulnerável ao algoritmo de Shor |
| QSC-002 | CRITICAL | ECDSA / ECDH / curvas elípticas |
| QSC-003 | CRITICAL | Diffie-Hellman clássico |
| QSC-010 | HIGH | MD5 — criptograficamente quebrado |
| QSC-011 | HIGH | SHA-1 — oficialmente quebrado (2017) |
| QSC-012 | HIGH | AES-ECB — semanticamente inseguro |
| QSC-013 | HIGH | DES / 3DES — depreciado NIST 2023 |
| QSC-014 | CRITICAL | RC4 — proibido no TLS (RFC 7465) |
| QSC-020 | CRITICAL | JWT algoritmo "none" |
| QSC-021 | MEDIUM | JWT HMAC simétrico (HS256/384/512) |
| QSC-022 | CRITICAL | JWT assinado com RSA |
| QSC-030 | HIGH | Segredos hardcoded |
| QSC-031 | HIGH | Semente aleatória previsível |
| QSC-040 | HIGH | Memória com chaves não zeroizada |

### Language Adapters
Regras específicas por linguagem para APIs nativas:

| Linguagem | APIs detectadas |
|-----------|----------------|
| Python | PyCryptodome, cryptography, hashlib, passlib, Flask-JWT |
| Java | JCE, Bouncy Castle, Spring Security, JSSE |
| C# | System.Security.Cryptography, BouncyCastle .NET |
| Go | crypto/rsa, crypto/ecdsa, crypto/md5, x/crypto |
| JavaScript/TypeScript | Node.js crypto, jsonwebtoken, CryptoJS, node-forge |

### Taint Analysis
Rastreia fluxo de dados externos até operações criptográficas:

```python
# OmniUil AI detecta este fluxo automaticamente:
algoritmo = request.json.get("alg")        # ← fonte: HTTP request
token = jwt.encode(data, key, algorithm=algoritmo)  # ← sink: JWT
# ALERTA: atacante pode enviar {"alg": "none"} e bypassar verificação
```

### Regras YAML Customizáveis
Adicione regras sem recompilar:

```yaml
# .omniuil-ai/rules/minhas-regras.yaml
rules:
  - id: "CUSTOM-001"
    severity: "CRITICAL"
    title: "API legada insegura"
    pattern: "api_v1_insecure\\("
    languages: ["python"]
```

### Grafo de Evidências
Contexto visual de código ao redor de cada finding:

```
┌─ QSC-001 (CRITICAL) ─ RSA detectado ──────────────────────┐
│ 📄 src/auth.py
│   17 │ def gerar_chave():
│   18 │     tamanho = config.get("key_size")
│►  19 │     chave = RSA.generate(tamanho)  ← VULNERÁVEL
│   20 │     return chave
└────────────────────────────────────────────────────────────┘
```

### PQC Engine (NIST FIPS 203/204)
```
KEM:  X25519 + ML-KEM-1024  (Proteção HNDL)
DSA:  Ed25519 + ML-DSA-87   (Assinaturas híbridas)
Sym:  AES-256-GCM            (Criptografia simétrica)
KDF:  HKDF-SHA3-256          (Derivação de chaves)
JWT:  PQC-JWT                (Tokens pós-quânticos)
```

### 5 Agentes IA (Ollama local — sem API key)
- **ScannerAgent** — escaneia projetos autonomamente
- **AnalysisAgent** — calcula Quantum Risk Score (0-100)
- **RemediationAgent** — sugere correções específicas
- **MonitoringAgent** — monitora regressões em tempo real
- **IncidentAgent** — responde a alertas críticos

---

## Instalação em 1 Comando

### Linux / macOS / WSL2
```bash
git clone https://github.com/Uilcol/omniuil-ai.git
cd omniuil-ai/omniuil-ai-enterprise
bash install.sh
```

### Windows (PowerShell Admin)
```powershell
git clone https://github.com/Uilcol/omniuil-ai.git
cd omniuil-ai\omniuil-ai-enterprise
.\install.ps1
```

**Resultado:** Dashboard em `http://localhost:8080`  
**Credenciais:** Salvas em `~/.omniuil-ai/ACESSO.txt`

### Pré-requisitos
- Docker Desktop
- Rust / Cargo (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- ~4 GB de espaço (modelo de IA incluído)

---

## CLI

```bash
# Compilar o engine
cd omniuil-ai-rust && cargo build --release

# Escanear um projeto
./target/release/omniuil-ai scan ./meu-projeto --format text

# Saída JSON (para CI/CD)
./target/release/omniuil-ai scan ./meu-projeto --format json

# Saída SARIF (GitHub Code Scanning)
./target/release/omniuil-ai scan ./meu-projeto --format sarif

# Gerar SBOM CycloneDX 1.5
./target/release/omniuil-ai sbom ./meu-projeto

# Assinar artefato com PQC híbrido
./target/release/omniuil-ai sign ./release.tar.gz

# Emitir PQC-JWT
./target/release/omniuil-ai token issue --subject user@empresa.com --ttl 3600
```

---

## API REST

```bash
# Autenticar
curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id": "meu-app", "client_secret": "SUA_SENHA"}'

# Escanear projeto
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/caminho/do/projeto"}'

# Verificar resultado
curl http://localhost:8080/api/v1/scan/JOB_ID \
  -H "Authorization: Bearer SEU_TOKEN"
```

---

## Integração CI/CD

### GitHub Actions
```yaml
- name: OmniUil AI Security Scan
  uses: Uilcol/omniuil-ai@v3.3.0
  with:
    path: ./src
    fail-on: CRITICAL,HIGH
    format: sarif
```

### Docker
```bash
# Iniciar
cd ~/.omniuil-ai && docker compose up -d

# Parar
docker compose down

# Logs
docker compose logs -f

# Atualizar
docker compose pull && docker compose up -d
```

---

## Arquitetura

```
┌─────────────────────────────────────────────────────┐
│                   OmniUil AI v3.3.0                       │
├──────────────┬──────────────┬───────────────────────┤
│  omniuil-ai-rust   │  omniuil-ai-agents │  omniuil-ai-enterprise      │
│  (Engine)    │  (IA Local)  │  (API + Dashboard)    │
├──────────────┼──────────────┼───────────────────────┤
│ Scanner PQC  │ ScannerAgent │ API REST (22 endpoints)│
│ Taint Engine │ AnalysisAgent│ Dashboard Web          │
│ Lang Adapters│ RemediationAg│ Auth HMAC-SHA3         │
│ YAML Rules   │ MonitoringAg │ SQLite Persistence     │
│ Evidence Graph│ IncidentAgent│ Rate Limiting          │
│ PQC Engine   │ Orchestrator │ Docker 3-stage         │
│ SBOM CycloneDX│ AgentBus    │ GitHub Actions CI/CD   │
│ PQC-JWT      │ SharedMemory │ Python SDK             │
│ SARIF Export │ LLM Abstração│ SSE Streaming          │
└──────────────┴──────────────┴───────────────────────┘
        ↑                              ↑
   #![forbid(unsafe_code)]      Ollama local
   ML-KEM-1024 + ML-DSA-87     (sem API key)
   AES-256-GCM + HKDF-SHA3     (dados ficam
                                 na sua máquina)
```

---

## Por que OmniUil AI?

| | OmniUil AI | Semgrep | Snyk | SandboxAQ |
|---|---|---|---|---|
| Detecção PQC | ✅ | ❌ | ❌ | ✅ |
| Taint Analysis Crypto | ✅ | Parcial | ❌ | ❌ |
| IA local (sem API key) | ✅ | ❌ | ❌ | ❌ |
| SBOM CycloneDX 1.5 | ✅ | ❌ | ✅ | ❌ |
| PQC-JWT nativo | ✅ | ❌ | ❌ | ❌ |
| 1-comando install | ✅ | ✅ | ✅ | ❌ |
| Preço | Acessível | Freemium | Pago | Enterprise |

---

## Conformidade

| Padrão | Status |
|--------|--------|
| NIST FIPS 203 (ML-KEM) | ✅ Implementado |
| NIST FIPS 204 (ML-DSA) | ✅ Implementado |
| CNSA 2.0 (obrigatório 2027) | ✅ Checklist completo |
| LGPD / ANPD Brasil | ✅ Dados locais, sem cloud |
| CycloneDX 1.5 (SBOM) | ✅ Implementado |
| SLSA Level 2+ | ✅ Build attestation |
| SARIF 2.1.0 | ✅ GitHub Code Scanning |

---

## Gestão do Stack

```bash
# Iniciar o OmniUil AI
cd ~/.omniuil-ai && docker compose up -d

# Ver status
docker compose ps

# Ver senha de acesso
cat ~/.omniuil-ai/ACESSO.txt

# Acessar dashboard
# http://localhost:8080

# Parar
docker compose down
```

---

## Licença

MIT License — veja [LICENSE](LICENSE)

---

## Contato

Projeto desenvolvido no Brasil 🇧🇷  
Repositório: [github.com/Uilcol/omniuil-ai](https://github.com/Uilcol/omniuil-ai)
