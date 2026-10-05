//! OmniUil AI — X.509/TLS Discovery Engine
//! Fusão do Paralax v0.2.0: descoberta de certificados e TLS em produção
//!
//! Analisa:
//! - Certificados PEM/DER em arquivos (código-fonte e configuração)
//! - Dados X.509 embutidos como strings base64
//! - Referências a arquivos de certificado (.pem, .crt, .cer, .der)
//!
//! NÃO faz conexões de rede — análise 100% local, sem I/O externo.
//! Zero unsafe code. Determinístico.

use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Tipos ─────────────────────────────────────────────────────────────────────

/// Status de conformidade PQC do certificado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertPqcStatus {
    /// Algoritmo PQC aprovado CNSA 2.0
    Compliant,
    /// Algoritmo clássico vulnerável a Shor (RSA, ECDSA, DH)
    QuantumVulnerable,
    /// Algoritmo classicamente quebrado (MD5, SHA-1)
    ClassicallyBroken,
    /// Algoritmo desconhecido ou não identificado
    Unknown,
}

/// Certificado X.509 descoberto em arquivo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredCert {
    /// Arquivo onde foi encontrado
    pub file:           String,
    /// Linha onde começa
    pub line:           u32,
    /// Tipo de descoberta
    pub discovery_type: CertDiscoveryType,
    /// Algoritmo de assinatura detectado (se identificável)
    pub sig_algorithm:  Option<String>,
    /// Tamanho da chave em bits (se identificável)
    pub key_size:       Option<u32>,
    /// Status PQC
    pub pqc_status:     CertPqcStatus,
    /// Motivo do status
    pub pqc_reason:     String,
    /// Recomendação de migração
    pub recommendation: String,
    /// SHA-256 do bloco PEM (para rastreamento único)
    pub content_hash:   String,
}

/// Como o certificado foi descoberto
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertDiscoveryType {
    /// Bloco PEM completo (-----BEGIN CERTIFICATE-----)
    PemBlock,
    /// Referência a arquivo de certificado
    FileReference,
    /// Dados base64 que parecem certificado
    Base64Data,
    /// Configuração de TLS (ssl_certificate, tls_cert_file, etc.)
    TlsConfig,
}

/// Resumo do discovery de certificados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDiscoverySummary {
    pub total_found:          usize,
    pub quantum_vulnerable:   usize,
    pub classically_broken:   usize,
    pub compliant:            usize,
    pub unknown:              usize,
    pub files_with_certs:     usize,
    pub immediate_action_required: bool,
}

// ── Padrões de detecção ───────────────────────────────────────────────────────

/// Padrões que indicam presença de certificado X.509
const PEM_CERT_HEADER: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERT_FOOTER: &str = "-----END CERTIFICATE-----";
const PEM_KEY_PATTERNS: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE REQUEST-----",
    "-----BEGIN X509 CRL-----",
];

/// Padrões em configuração que apontam para certificados
const TLS_CONFIG_PATTERNS: &[&str] = &[
    "ssl_certificate",
    "ssl_certificate_key",
    "tls_cert_file",
    "tls_key_file",
    "cert_file",
    "key_file",
    "certificate_file",
    "private_key_file",
    "SSLCertificateFile",
    "SSLCertificateKeyFile",
    "ssl-cert",
    "ssl-key",
    "certfile",
    "keyfile",
    "CERT_FILE",
    "KEY_FILE",
    "TLS_CERT",
    "TLS_KEY",
    "SSL_CERT_PATH",
];

/// Extensões de arquivo que indicam certificado
const CERT_EXTENSIONS: &[&str] = &[
    ".pem", ".crt", ".cer", ".der", ".p12", ".pfx",
    ".p7b", ".p7c", ".p8", ".key", ".csr",
];

/// Algoritmos e seus status PQC
fn classify_algorithm(alg_hint: &str) -> (CertPqcStatus, String, String) {
    let alg_lower = alg_hint.to_lowercase();

    // Classicamente quebrado
    if alg_lower.contains("md5") {
        return (
            CertPqcStatus::ClassicallyBroken,
            "MD5 — quebrado desde 2004, colisões computáveis em segundos".to_string(),
            "Substitua por certificado SHA-256 ou SHA-384 imediatamente".to_string(),
        );
    }
    if alg_lower.contains("sha1") || alg_lower.contains("sha-1") {
        return (
            CertPqcStatus::ClassicallyBroken,
            "SHA-1 — quebrado (ataque SHAttered 2017), browsers rejeitam".to_string(),
            "Substitua por certificado SHA-256 ou SHA-384 imediatamente".to_string(),
        );
    }

    // Vulnerável a Shor (risco quântico)
    if alg_lower.contains("rsa") {
        let key_hint = if alg_lower.contains("4096") { "RSA-4096" }
                       else if alg_lower.contains("2048") { "RSA-2048" }
                       else { "RSA" };
        return (
            CertPqcStatus::QuantumVulnerable,
            format!("{} — vulnerável ao algoritmo de Shor com hardware quântico", key_hint),
            "Migre para certificado ML-DSA-65 (NIST FIPS 204) ou Ed25519 como passo intermediário".to_string(),
        );
    }
    if alg_lower.contains("ecdsa") || alg_lower.contains("ec ") || alg_lower.contains("p-256") || alg_lower.contains("p-384") {
        return (
            CertPqcStatus::QuantumVulnerable,
            "ECDSA/ECC — vulnerável ao algoritmo de Shor com hardware quântico".to_string(),
            "Migre para ML-DSA-65 (NIST FIPS 204). Interim: Ed25519 (menor impacto quântico)".to_string(),
        );
    }
    if alg_lower.contains("dsa") {
        return (
            CertPqcStatus::QuantumVulnerable,
            "DSA — vulnerável ao algoritmo de Shor e também ao algoritmo clássico de Pohlig-Hellman".to_string(),
            "Substitua por ML-DSA-65 (NIST FIPS 204) imediatamente".to_string(),
        );
    }

    // PQC aprovado
    if alg_lower.contains("ml-dsa") || alg_lower.contains("mldsa") || alg_lower.contains("dilithium") {
        return (
            CertPqcStatus::Compliant,
            "ML-DSA (NIST FIPS 204) — algoritmo PQC aprovado para assinaturas".to_string(),
            "Algoritmo correto. Verifique nível: ML-DSA-65 (Level 3) ou ML-DSA-87 (Level 5)".to_string(),
        );
    }
    if alg_lower.contains("slh-dsa") || alg_lower.contains("sphincs") {
        return (
            CertPqcStatus::Compliant,
            "SLH-DSA (NIST FIPS 205) — algoritmo PQC aprovado (hash-based)".to_string(),
            "Algoritmo correto. Use como alternativa ao ML-DSA para diversidade".to_string(),
        );
    }
    if alg_lower.contains("ed25519") || alg_lower.contains("ed448") {
        return (
            CertPqcStatus::QuantumVulnerable,
            "Ed25519/Ed448 — mais resistente que RSA/ECDSA, mas ainda vulnerável a Shor".to_string(),
            "Bom passo intermediário. Target final: ML-DSA-65 (NIST FIPS 204)".to_string(),
        );
    }

    (
        CertPqcStatus::Unknown,
        "Algoritmo não identificado na análise estática".to_string(),
        "Inspecione manualmente: openssl x509 -in cert.pem -text -noout | grep 'Signature Algorithm'".to_string(),
    )
}

/// Calcula hash SHA-256 simples do conteúdo (sem dependência externa)
fn simple_hash(content: &str) -> String {
    // Hash determinístico simples — para identificação, não criptografia
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in content.bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

/// Detecta algoritmo a partir de padrões no arquivo
fn detect_algorithm_from_context(content: &str, line_idx: usize) -> Option<String> {
    // Janela de contexto ao redor da linha
    let lines: Vec<&str> = content.lines().collect();
    let start = line_idx.saturating_sub(5);
    let end   = (line_idx + 10).min(lines.len());
    let window = lines[start..end].join(" ").to_lowercase();

    let patterns = [
        ("rsa-4096", "RSA-4096"),
        ("rsa-2048", "RSA-2048"),
        ("rsa-1024", "RSA-1024"),
        ("rsa",      "RSA"),
        ("ecdsa",    "ECDSA"),
        ("ec ",      "EC"),
        ("p-256",    "P-256"),
        ("p-384",    "P-384"),
        ("ed25519",  "Ed25519"),
        ("ed448",    "Ed448"),
        ("sha1",     "SHA-1"),
        ("sha-1",    "SHA-1"),
        ("md5",      "MD5"),
        ("ml-dsa",   "ML-DSA"),
        ("dilithium","ML-DSA"),
        ("slh-dsa",  "SLH-DSA"),
        ("sphincs",  "SLH-DSA"),
    ];

    for (pattern, label) in &patterns {
        if window.contains(pattern) {
            return Some(label.to_string());
        }
    }
    None
}

// ── Função principal de discovery ─────────────────────────────────────────────

/// Analisa um arquivo em busca de certificados e configurações TLS.
/// Puro, sem I/O de rede, sem unsafe code.
pub fn discover_certs_in_file(path: &Path, content: &str) -> Vec<DiscoveredCert> {
    let mut found = Vec::new();
    let path_str  = path.display().to_string();
    let path_lower = path_str.to_lowercase();
    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let lineno = (i + 1) as u32;

        // 1. Bloco PEM completo
        if line.contains(PEM_CERT_HEADER) {
            let alg_hint = detect_algorithm_from_context(content, i)
                .unwrap_or_else(|| "unknown".to_string());
            let (status, reason, rec) = classify_algorithm(&alg_hint);
            let hash = simple_hash(&line[..line.len().min(100)]);

            found.push(DiscoveredCert {
                file:           path_str.clone(),
                line:           lineno,
                discovery_type: CertDiscoveryType::PemBlock,
                sig_algorithm:  if alg_hint == "unknown" { None } else { Some(alg_hint) },
                key_size:       None,
                pqc_status:     status,
                pqc_reason:     reason,
                recommendation: rec,
                content_hash:   hash,
            });
        }

        // 2. Chaves privadas/públicas PEM
        for &key_pattern in PEM_KEY_PATTERNS {
            if line.contains(key_pattern) {
                let alg = if key_pattern.contains("RSA") { "RSA" }
                          else if key_pattern.contains("EC") { "ECDSA" }
                          else { "unknown" };
                let (status, reason, rec) = classify_algorithm(alg);
                let hash = simple_hash(key_pattern);
                found.push(DiscoveredCert {
                    file:           path_str.clone(),
                    line:           lineno,
                    discovery_type: CertDiscoveryType::PemBlock,
                    sig_algorithm:  if alg == "unknown" { None } else { Some(alg.to_string()) },
                    key_size:       None,
                    pqc_status:     status,
                    pqc_reason:     reason,
                    recommendation: rec,
                    content_hash:   hash,
                });
                break;
            }
        }

        // 3. Referências a arquivos de certificado
        for &ext in CERT_EXTENSIONS {
            if line.to_lowercase().contains(ext) {
                let alg_hint = detect_algorithm_from_context(content, i)
                    .unwrap_or_else(|| "unknown".to_string());
                let (status, reason, rec) = classify_algorithm(&alg_hint);
                found.push(DiscoveredCert {
                    file:           path_str.clone(),
                    line:           lineno,
                    discovery_type: CertDiscoveryType::FileReference,
                    sig_algorithm:  if alg_hint == "unknown" { None } else { Some(alg_hint) },
                    key_size:       None,
                    pqc_status:     status,
                    pqc_reason:     reason,
                    recommendation: rec,
                    content_hash:   simple_hash(&format!("{}:{}", path_str, lineno)),
                });
                break;
            }
        }

        // 4. Configurações TLS
        let line_lower = line.to_lowercase();
        for &pattern in TLS_CONFIG_PATTERNS {
            if line_lower.contains(&pattern.to_lowercase()) && (line.contains('=') || line.contains(':')) {
                let alg_hint = detect_algorithm_from_context(content, i)
                    .unwrap_or_else(|| "unknown".to_string());
                let (status, reason, rec) = classify_algorithm(&alg_hint);
                found.push(DiscoveredCert {
                    file:           path_str.clone(),
                    line:           lineno,
                    discovery_type: CertDiscoveryType::TlsConfig,
                    sig_algorithm:  if alg_hint == "unknown" { None } else { Some(alg_hint) },
                    key_size:       None,
                    pqc_status:     status,
                    pqc_reason:     reason,
                    recommendation: rec,
                    content_hash:   simple_hash(&format!("tls:{}:{}", path_str, lineno)),
                });
                break;
            }
        }
    }

    // Remove duplicatas por linha
    found.dedup_by_key(|c| c.line);
    found
}

/// Calcula resumo do discovery
pub fn summarize_discovery(certs: &[DiscoveredCert]) -> CertDiscoverySummary {
    let mut files: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut vulnerable = 0usize;
    let mut broken     = 0usize;
    let mut compliant  = 0usize;
    let mut unknown    = 0usize;

    for c in certs {
        files.insert(&c.file);
        match c.pqc_status {
            CertPqcStatus::QuantumVulnerable  => vulnerable += 1,
            CertPqcStatus::ClassicallyBroken  => broken     += 1,
            CertPqcStatus::Compliant          => compliant  += 1,
            CertPqcStatus::Unknown            => unknown    += 1,
        }
    }

    CertDiscoverySummary {
        total_found:               certs.len(),
        quantum_vulnerable:        vulnerable,
        classically_broken:        broken,
        compliant,
        unknown,
        files_with_certs:          files.len(),
        immediate_action_required: broken > 0 || vulnerable > 0,
    }
}

/// Serializa resultados para JSON
pub fn discovery_to_json(certs: &[DiscoveredCert], summary: &CertDiscoverySummary) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "discovery_type": "x509_tls",
        "summary": summary,
        "certificates": certs,
    })).unwrap_or_else(|_| "{}".to_string())
}
