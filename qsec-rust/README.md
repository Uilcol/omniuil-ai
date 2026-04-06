# QSEC v3 — Post-Quantum Cryptographic Firewall

**Infraestrutura de confiança criptográfica para a era da computação quântica.**  
Escrito em Rust. Zero unsafe code. Zeroização automática de chaves. Tempo constante em todas as comparações secretas.

---

## Estrutura do Projeto

```
qsec-rust/
├── Cargo.toml                  ← Dependências + feature flags
├── README.md
├── src/
│   ├── lib.rs                  ← API pública + QsecPlatform
│   ├── main.rs                 ← CLI (clap derive)
│   ├── error.rs                ← Hierarquia de erros tipados
│   ├── pqc_engine.rs           ← Pilar 2: Motor PQC Híbrido
│   ├── scanner.rs              ← Pilar 1: Crypto Scanner
│   ├── supply_chain.rs         ← Pilar 3: SBOM + Signing + Attestation
│   └── zero_trust.rs           ← Pilar 4: PQC-JWT + KeyRegistry + APIKeys
└── tests/
    └── integration_tests.rs    ← 50+ testes de integração
```

---

## Instalação Rápida

```bash
# 1. Clone o projeto
git clone https://github.com/yourorg/qsec-rust
cd qsec-rust

# 2. Build padrão (backend de referência estrutural)
cargo build --release

# 3. (Recomendado) PQC real NIST FIPS 203/204 via liboqs
#    Ubuntu/Debian:
apt-get install liboqs-dev
cargo build --release --features liboqs

#    macOS:
brew install liboqs
cargo build --release --features liboqs

# 4. Instala o binário
cargo install --path .

# 5. Roda os testes
cargo test

# 6. Com PQC real:
cargo test --features liboqs
```

---

## Os 4 Pilares

### Pilar 1 — Crypto Scanner

Escaneia código-fonte em busca de criptografia fraca ou não preparada para quânticos.

```bash
# Texto legível
qsec scan ./src

# JSON para CI/CD
qsec scan ./src --format json

# Falha o build se encontrar CRITICAL ou HIGH
qsec scan ./src --fail-on-critical
```

**Regras implementadas:**

| ID | Severidade | Detecta |
|----|-----------|---------|
| QSC-001 | CRITICAL | RSA (Shor) |
| QSC-002 | CRITICAL | ECDSA / ECDH (Shor) |
| QSC-003 | CRITICAL | Diffie-Hellman clássico |
| QSC-010 | HIGH | MD5 |
| QSC-011 | HIGH | SHA-1 (SHAttered 2017) |
| QSC-012 | HIGH | AES-ECB |
| QSC-013 | HIGH | DES / 3DES (NIST depreciado 2023) |
| QSC-014 | CRITICAL | RC4 (RFC 7465 proibido) |
| QSC-020 | CRITICAL | JWT `alg: none` |
| QSC-021 | MEDIUM | JWT HMAC simétrico |
| QSC-022 | CRITICAL | JWT RS256/RS384/RS512 |
| QSC-030 | HIGH | Segredos hardcoded |
| QSC-031 | HIGH | RNG não-criptográfico |
| QSC-040 | HIGH | Crates Rust vulneráveis |

---

### Pilar 2 — PQC Engine

Motor de criptografia híbrida: Clássico + Pós-Quântico.

```rust
use qsec::pqc_engine::PqcEngine;

let engine = PqcEngine::new();

// KEM híbrido — X25519 + ML-KEM-1024
let kem_keys  = engine.generate_kem_keypair()?;
let ciphertext = engine.hybrid_encrypt(b"dado secreto", &kem_keys.public_key, None)?;
let plaintext  = engine.hybrid_decrypt(&ciphertext, &kem_keys, None)?;

// DSA híbrido — Ed25519 + ML-DSA-87
let dsa_keys = engine.generate_dsa_keypair()?;
let sig      = engine.hybrid_sign(b"artefato", &dsa_keys)?;
let ok       = engine.hybrid_verify(b"artefato", &sig, &dsa_keys.public_key)?;
```

**Proteção HNDL (Harvest Now, Decrypt Later):**
```
SS_C    = X25519(ephemeral_sk, recipient_pk)      ← clássico
SS_PQC  = ML-KEM-Decap(recipient_pk, ct_pq)       ← pós-quântico
AES_KEY = HKDF-SHA3-256(SS_C || SS_PQC)           ← combinado
CT      = AES-256-GCM(AES_KEY, plaintext)

Adversário precisa quebrar AMBOS para decriptar.
```

**Segurança de memória em Rust:**
- `ZeroizeOnDrop` em `KemPrivateKey` e `DsaPrivateKey` — chaves privadas zeradas no `drop()`, garantido pelo compilador
- `Debug` nunca expõe material privado: `[PRIVATE KEY REDACTED]`
- `#![forbid(unsafe_code)]` — zero código unsafe

---

### Pilar 3 — Supply Chain Protection

```bash
# Assina artefato
qsec sign ./dist/app --out ./dist/app.qsec.json

# Verifica integridade
qsec verify ./dist/app --manifest ./dist/app.qsec.json

# Gera SBOM CycloneDX 1.5
qsec sbom ./meu-projeto --out sbom.cyclonedx.json

# Pipeline completo
qsec pipeline ./src --artifacts dist/app,dist/lib.so --out-dir ./qsec-reports
```

```rust
use qsec::supply_chain::{ArtifactSigner, AttestationBuilder};

let signer = ArtifactSigner::new(&engine, &signing_keypair);
let sa     = signer.sign(Path::new("./app"), None)?;
signer.verify(Path::new("./app"), &sa)?;  // Err se adulterado

let builder = AttestationBuilder::new(&engine, &signing_keypair, "ci-pipeline");
let att     = builder.attest(&[Path::new("./app")], Some("https://github.com/..."), None, None)?;
builder.verify(&att)?;
```

**Verificação de integridade em ordem segura:**
1. Arquivo existe
2. Tamanho correto
3. SHA3-256 (comparação em tempo constante)
4. Assinatura PQC híbrida

---

### Pilar 4 — Zero Trust Identity

```bash
# Emite PQC-JWT
qsec token issue --subject alice@example.com --ttl 3600 --audience api.example.com

# Verifica
qsec token verify --token <jwt> --audience api.example.com

# Cria API Key
qsec apikey create --name service-ml --scope read,write --ttl-days 90

# Status das chaves
qsec keys status
```

```rust
use qsec::zero_trust::{PqcJwtManager, ApiKeyManager};

// JWT
let mgr   = PqcJwtManager::new(&engine, &registry);
let token = mgr.issue("user@example.com", HashMap::new(), 3600, "api.example.com", "qsec")?;
let claims = mgr.verify(&token, "api.example.com", None)?;

// API Keys
let mut keys = ApiKeyManager::new();
let (key_id, raw_key) = keys.create("service", vec!["read".into()], Some(90))?;
let entry = keys.verify(&raw_key, Some("read"))?;
```

**Formato do token:** `header.payload.ed25519_sig.mldsa_sig` (4 partes)

**Ordem de verificação JWT (segura contra timing attacks):**
1. Estrutura (4 partes)
2. Algoritmo — rejeita `none`, `RS*`, `HS*`, `ES*`
3. **Revogação — ANTES da expiração** (evita oracle de timing)
4. Expiração
5. iat no futuro (detecta replay attacks)
6. Audience
7. Chave por kid
8. Assinatura híbrida Ed25519 + ML-DSA

---

## CLI Completa

```bash
qsec scan    <path> [--format text|json] [--fail-on-critical]
qsec sign    <artifact> [--out <manifest.json>]
qsec verify  <artifact> --manifest <manifest.json>
qsec sbom    <project>  [--out <sbom.json>]
qsec keys    status | rotate | revoke --key-id <kid>
qsec token   issue  --subject <sub> [--ttl 3600] [--audience <aud>] [--claims '{"role":"admin"}']
qsec token   verify --token <jwt> [--audience <aud>]
qsec apikey  create --name <n> --scope read,write [--ttl-days 90]
qsec apikey  verify --key <raw> [--scope <s>]
qsec apikey  revoke --key-id <kid>
qsec apikey  list
qsec pipeline <project> [--artifacts a,b,c] [--out-dir ./qsec-out] [--repo <url>]
qsec info
```

---

## Garantias de Segurança

| Propriedade | Mecanismo |
|---|---|
| Zeroização de chaves | `zeroize::ZeroizeOnDrop` — garantido em tempo de compilação |
| Sem unsafe code | `#![forbid(unsafe_code)]` |
| Timing-safe comparisons | `subtle::ConstantTimeEq` em todos os segredos |
| Memória sem GC | Rust ownership — sem garbage collector, sem use-after-free |
| Erros tipados | `thiserror` — sem strings de erro ambíguas |
| HNDL protection | HKDF(SS_clássico \|\| SS_pqc) — ambos precisam ser quebrados |
| JWT seguro | Revogação ANTES da expiração — sem oracle de timing |
| API Keys | SHA3-256, nunca plaintext, prefixo validado antes do hash |

---

## Feature Flags

```toml
# Cargo.toml
[features]
default = []
liboqs  = ["dep:oqs"]   # ML-KEM/ML-DSA reais (NIST FIPS 203/204)
```

Sem `liboqs`: backend de referência estrutural (desenvolvimento).  
Com `liboqs`: `ML-KEM-1024` e `ML-DSA-87` reais, auditados, NIST FIPS 203/204.

---

## Integração CI/CD

```yaml
# GitHub Actions
- name: QSEC Security Scan
  run: |
    cargo build --release
    ./target/release/qsec scan ./src --format json --fail-on-critical
    ./target/release/qsec sbom . --out sbom.cyclonedx.json
    ./target/release/qsec sign ./target/release/myapp
    ./target/release/qsec pipeline . --artifacts target/release/myapp --out-dir security-reports
```

---

## Dependências Core

| Crate | Função | Auditoria |
|-------|--------|-----------|
| `ed25519-dalek` | Ed25519 | Auditada — Cryptography.io |
| `x25519-dalek` | X25519 | Auditada — Cryptography.io |
| `aes-gcm` | AES-256-GCM | Auditada — RustCrypto |
| `hkdf` + `sha3` | HKDF-SHA3-256 | Auditadas — RustCrypto |
| `zeroize` | Zeroização de memória | Auditada — RustCrypto |
| `subtle` | Tempo constante | Auditada — Cryptography.io |
| `oqs` (opcional) | ML-KEM + ML-DSA | Open Quantum Safe (NIST) |
| `clap` | CLI | Padrão da indústria Rust |
| `thiserror` | Erros tipados | Padrão da indústria Rust |
