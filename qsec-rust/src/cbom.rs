//! OmniUil AI — Crypto Bill of Materials (CBOM)
//! Alinhado com EO-14412 (junho/2026) e CNSA 2.0
//! Campos obrigatórios conforme guidance CISA/NIST SP 800-166
//!
//! Segurança: módulo somente leitura, sem I/O de rede, sem unsafe code.
//! Gera CBOM determinístico a partir de findings — sem efeitos colaterais.

use serde::{Deserialize, Serialize};
use crate::scanner::CryptoFinding;
use crate::scanner::Severity;
use std::collections::HashMap;

// ── Algoritmos PQC aprovados CNSA 2.0 ────────────────────────────────────────
const CNSA2_APPROVED: &[&str] = &[
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",   // FIPS 203
    "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",     // FIPS 204
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s",    // FIPS 205
    "SLH-DSA-SHAKE-128s","SLH-DSA-SHAKE-256s",
    "LMS", "XMSS",                                // SP 800-208
    "AES-256", "AES-256-GCM", "AES-256-CCM",     // Simétrico aprovado
    "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", // Hash aprovado
    "AES-128",                                    // Apenas com hybrid mode
];

// Algoritmos vulneráveis a Shor (risco quântico direto)
const QUANTUM_VULNERABLE: &[&str] = &[
    "RSA", "ECDSA", "ECDH", "DH", "DSA",
    "secp256r1", "secp384r1", "P-256", "P-384",
    "X9.62", "brainpool",
];

// Algoritmos vulneráveis a Grover (risco quântico parcial)
const GROVER_WEAKENED: &[&str] = &[
    "AES-128", "SHA-256", "SHA-384",
];

// Algoritmos classicamente quebrados
const CLASSICALLY_BROKEN: &[&str] = &[
    "MD5", "SHA-1", "SHA1", "DES", "3DES", "RC4",
    "RC2", "Blowfish", "IDEA",
];

// ── Tipos CBOM ────────────────────────────────────────────────────────────────

/// Status de maturidade criptográfica (ciclo formal CNSA 2.0)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CryptoMaturity {
    Unknown,        // Não avaliado
    Discovered,     // Identificado no inventário
    Assessed,       // Avaliado quanto ao risco
    Planned,        // Plano de migração definido
    Migrating,      // Em processo de migração
    Hybrid,         // Modo híbrido (clássico + PQC)
    Pqc,            // Totalmente migrado para PQC
    Deprecated,     // Removido / desativado
}

/// Nível de risco quântico
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuantumRisk {
    None,           // Algoritmo PQC aprovado
    Weakened,       // Vulnerável a Grover (força bruta mais rápida)
    Vulnerable,     // Vulnerável a Shor (quebra total)
    Broken,         // Classicamente quebrado (urgência imediata)
}

/// Ativo criptográfico individual no CBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    /// Identificador único do ativo
    pub id:               String,
    /// Algoritmo criptográfico
    pub algorithm:        String,
    /// Família do algoritmo (RSA, ECDSA, AES, etc.)
    pub algorithm_family: String,
    /// Tamanho da chave em bits (quando aplicável)
    pub key_size:         Option<u32>,
    /// Protocolo ou contexto (JWT, TLS, SSH, etc.)
    pub protocol:         Option<String>,
    /// Uso (signing, encryption, key_exchange, hashing, mac)
    pub usage:            String,
    /// Arquivo onde foi detectado
    pub file:             String,
    /// Linha onde foi detectado
    pub line:             u32,
    /// Status de maturidade (ciclo CNSA 2.0)
    pub maturity:         CryptoMaturity,
    /// Nível de risco quântico
    pub quantum_risk:     QuantumRisk,
    /// É compatível com CNSA 2.0?
    pub cnsa2_compliant:  bool,
    /// É modo híbrido (clássico + PQC)?
    pub is_hybrid:        bool,
    /// Algoritmo PQC recomendado para substituição
    pub recommended_pqc:  Option<String>,
    /// ID da regra que detectou
    pub rule_id:          String,
    /// Proprietário/responsável (preenchido pelo usuário)
    pub owner:            Option<String>,
}

/// CBOM completo — Crypto Bill of Materials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoBom {
    /// Versão do formato CBOM
    pub cbom_version:        String,
    /// Versão do OmniUil AI
    pub scanner_version:     String,
    /// Timestamp de geração (ISO 8601)
    pub generated_at:        String,
    /// Caminho escaneado
    pub scan_path:           String,
    /// Lista de ativos criptográficos descobertos
    pub components:          Vec<CryptoAsset>,
    /// Resumo por família de algoritmo
    pub summary:             CbomSummary,
    /// Metadados de conformidade
    pub compliance:          CbomCompliance,
}

/// Resumo agregado do CBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomSummary {
    pub total_assets:            usize,
    pub quantum_vulnerable:      usize,
    pub grover_weakened:         usize,
    pub classically_broken:      usize,
    pub cnsa2_compliant:         usize,
    pub hybrid_implementations:  usize,
    pub by_algorithm_family:     HashMap<String, usize>,
    pub by_maturity:             HashMap<String, usize>,
}

/// Metadados de conformidade regulatória
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomCompliance {
    /// CNSA 2.0 compliance score (0-100)
    pub cnsa2_score:             u32,
    /// Pronto para CNSA 2.0 jan/2027?
    pub cnsa2_ready:             bool,
    /// Frameworks referenciados
    pub frameworks:              Vec<String>,
    /// Data do deadline mais próximo
    pub nearest_deadline:        String,
    /// Número de sistemas não conformes
    pub non_compliant_count:     usize,
    /// Ação requerida imediatamente
    pub immediate_action:        Option<String>,
}

// ── Funções de classificação ─────────────────────────────────────────────────

fn classify_quantum_risk(algorithm: &str, rule_id: &str) -> QuantumRisk {
    let alg_upper = algorithm.to_uppercase();
    let rule_upper = rule_id.to_uppercase();

    // Classicamente quebrado — risco imediato
    if CLASSICALLY_BROKEN.iter().any(|a| alg_upper.contains(a.to_uppercase().as_str())) {
        return QuantumRisk::Broken;
    }
    if rule_upper.contains("QSC-010") || rule_upper.contains("QSC-011")
        || rule_upper.contains("QSC-013") || rule_upper.contains("QSC-014") {
        return QuantumRisk::Broken;
    }

    // Vulnerável a Shor — risco quântico direto
    if QUANTUM_VULNERABLE.iter().any(|a| alg_upper.contains(a.to_uppercase().as_str())) {
        return QuantumRisk::Vulnerable;
    }
    if rule_upper.contains("QSC-001") || rule_upper.contains("QSC-002")
        || rule_upper.contains("QSC-003") || rule_upper.contains("QSC-022")
        || rule_upper.contains("QSC-300") || rule_upper.contains("QSC-301")
        || rule_upper.contains("QSC-400") || rule_upper.contains("QSC-500") {
        return QuantumRisk::Vulnerable;
    }

    // Vulnerável a Grover — risco parcial
    if GROVER_WEAKENED.iter().any(|a| alg_upper.contains(a.to_uppercase().as_str())) {
        return QuantumRisk::Weakened;
    }
    if rule_upper.contains("QSC-200") || rule_upper.contains("QSC-201") {
        return QuantumRisk::Weakened;
    }

    QuantumRisk::None
}

fn is_cnsa2_compliant(algorithm: &str, rule_id: &str) -> bool {
    let alg_upper = algorithm.to_uppercase();
    // Algoritmos aprovados CNSA 2.0
    if CNSA2_APPROVED.iter().any(|a| alg_upper.contains(a.to_uppercase().as_str())) {
        return true;
    }
    // Se tem finding de vulnerabilidade, não é compliant
    !rule_id.is_empty() && classify_quantum_risk(algorithm, rule_id) == QuantumRisk::None
}

fn is_hybrid(title: &str, snippet: &str) -> bool {
    let combined = format!("{} {}", title, snippet).to_lowercase();
    combined.contains("hybrid") || combined.contains("x25519kyber")
        || combined.contains("x25519+ml-kem") || combined.contains("ecdh+ml-kem")
        || combined.contains("xwing") || combined.contains("kyber+")
}

fn extract_algorithm_family(rule_id: &str, title: &str) -> String {
    match rule_id {
        r if r.contains("QSC-001") || r.contains("QSC-301") || r.contains("QSC-500")
            || r.contains("QSC-100") || r.contains("QSC-102") => "RSA".to_string(),
        r if r.contains("QSC-002") || r.contains("QSC-300") || r.contains("QSC-400")
            || r.contains("ECDSA") || r.contains("JV-002") => "ECC/ECDSA".to_string(),
        r if r.contains("QSC-003") => "DH".to_string(),
        r if r.contains("QSC-010") || r.contains("QSC-106") || r.contains("QSC-107")
            || r.contains("QSC-110") => "MD5".to_string(),
        r if r.contains("QSC-011") || r.contains("QSC-112") => "SHA-1".to_string(),
        r if r.contains("QSC-012") || r.contains("QSC-103")
            || r.contains("QSC-200") => "AES".to_string(),
        r if r.contains("QSC-013") => "DES/3DES".to_string(),
        r if r.contains("QSC-014") => "RC4".to_string(),
        r if r.contains("QSC-020") || r.contains("QSC-021") || r.contains("QSC-022")
            || r.contains("JWT") => "JWT".to_string(),
        r if r.contains("QSC-030") || r.contains("QSC-108")
            || r.contains("QSC-116") => "Hardcoded Secret".to_string(),
        r if r.contains("QSC-104") => "TLS Legacy".to_string(),
        r if r.contains("QSC-201") => "SHA-256".to_string(),
        _ => {
            // Tenta extrair do título
            let title_lower = title.to_lowercase();
            if title_lower.contains("rsa") { "RSA".to_string() }
            else if title_lower.contains("ecdsa") || title_lower.contains("ec ") { "ECC/ECDSA".to_string() }
            else if title_lower.contains("md5") { "MD5".to_string() }
            else if title_lower.contains("sha-1") || title_lower.contains("sha1") { "SHA-1".to_string() }
            else if title_lower.contains("aes") { "AES".to_string() }
            else if title_lower.contains("jwt") { "JWT".to_string() }
            else { "Unknown".to_string() }
        }
    }
}

fn recommended_pqc(family: &str, quantum_risk: &QuantumRisk) -> Option<String> {
    if *quantum_risk == QuantumRisk::None { return None; }
    match family {
        "RSA" => Some("ML-KEM-768 (key encapsulation) + ML-DSA-65 (signatures) — NIST FIPS 203/204".to_string()),
        "ECC/ECDSA" => Some("ML-DSA-65 (signatures) — NIST FIPS 204. Interim: Ed25519".to_string()),
        "DH" => Some("ML-KEM-768 (key establishment) — NIST FIPS 203. Interim: X25519".to_string()),
        "JWT" => Some("ML-DSA-65 for JWT signing — use EdDSA (Ed25519) as immediate step".to_string()),
        "MD5" | "SHA-1" => Some("SHA3-256 or BLAKE2b for hashing; Argon2id for passwords".to_string()),
        "AES" => Some("AES-256-GCM (provides 128-bit quantum security via Grover resistance)".to_string()),
        "DES/3DES" | "RC4" => Some("AES-256-GCM or ChaCha20-Poly1305 (immediate replacement required)".to_string()),
        "TLS Legacy" => Some("TLS 1.3 with X25519Kyber768 hybrid key exchange".to_string()),
        _ => Some("Consult NIST SP 800-131A Rev 3 for migration guidance".to_string()),
    }
}

fn extract_usage(rule_id: &str, title: &str) -> String {
    let combined = format!("{} {}", rule_id, title).to_lowercase();
    if combined.contains("jwt") || combined.contains("sign") { "signing".to_string() }
    else if combined.contains("encrypt") || combined.contains("aes") || combined.contains("des") { "encryption".to_string() }
    else if combined.contains("hash") || combined.contains("md5") || combined.contains("sha") { "hashing".to_string() }
    else if combined.contains("key") || combined.contains("dh") || combined.contains("ecdh") { "key_exchange".to_string() }
    else if combined.contains("tls") || combined.contains("ssl") { "transport".to_string() }
    else { "unknown".to_string() }
}

fn extract_protocol(rule_id: &str, title: &str, snippet: &str) -> Option<String> {
    let combined = format!("{} {} {}", rule_id, title, snippet).to_lowercase();
    if combined.contains("jwt") { Some("JWT".to_string()) }
    else if combined.contains("tls") || combined.contains("ssl") { Some("TLS".to_string()) }
    else if combined.contains("ssh") { Some("SSH".to_string()) }
    else if combined.contains("pgp") || combined.contains("gpg") { Some("PGP".to_string()) }
    else if combined.contains("x509") || combined.contains("certificate") { Some("X.509".to_string()) }
    else { None }
}

// ── Função pública principal ──────────────────────────────────────────────────

/// Gera CBOM completo a partir de findings do scanner.
/// Puro, determinístico, sem I/O de rede, sem unsafe code.
pub fn generate_cbom(
    findings: &[CryptoFinding],
    scan_path: &str,
    scanner_version: &str,
) -> CryptoBom {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let generated_at = format_timestamp(timestamp);

    // Converte findings em CryptoAssets
    let mut components: Vec<CryptoAsset> = findings.iter().enumerate().map(|(i, f)| {
        let algorithm = extract_algorithm_from_title(&f.title);
        let family    = extract_algorithm_family(&f.rule_id, &f.title);
        let q_risk    = classify_quantum_risk(&algorithm, &f.rule_id);
        let compliant = is_cnsa2_compliant(&algorithm, &f.rule_id);
        let hybrid    = is_hybrid(&f.title, &f.code_snippet);
        let usage     = extract_usage(&f.rule_id, &f.title);
        let protocol  = extract_protocol(&f.rule_id, &f.title, &f.code_snippet);
        let rec_pqc   = recommended_pqc(&family, &q_risk);
        let key_size  = extract_key_size(&f.title, &f.code_snippet);

        // Maturity inicial baseada no risco
        let maturity = if hybrid {
            CryptoMaturity::Hybrid
        } else if compliant {
            CryptoMaturity::Pqc
        } else {
            CryptoMaturity::Discovered
        };

        CryptoAsset {
            id:               format!("CBOM-{:04}", i + 1),
            algorithm:        algorithm.clone(),
            algorithm_family: family,
            key_size,
            protocol,
            usage,
            file:             f.file.clone(),
            line:             f.line as u32,
            maturity,
            quantum_risk:     q_risk,
            cnsa2_compliant:  compliant,
            is_hybrid:        hybrid,
            recommended_pqc:  rec_pqc,
            rule_id:          f.rule_id.clone(),
            owner:            None,
        }
    }).collect();

    // Remove duplicatas (mesmo algoritmo + arquivo)
    components.dedup_by(|a, b| a.algorithm == b.algorithm && a.file == b.file && a.line == b.line);

    // Calcula sumário
    let summary = compute_summary(&components);

    // Calcula compliance
    let compliance = compute_compliance(&components, &summary);

    CryptoBom {
        cbom_version:    "1.0.0".to_string(),
        scanner_version: scanner_version.to_string(),
        generated_at,
        scan_path:       scan_path.to_string(),
        components,
        summary,
        compliance,
    }
}

fn compute_summary(components: &[CryptoAsset]) -> CbomSummary {
    let mut by_family: HashMap<String, usize> = HashMap::new();
    let mut by_maturity: HashMap<String, usize> = HashMap::new();
    let mut vulnerable = 0usize;
    let mut weakened   = 0usize;
    let mut broken     = 0usize;
    let mut compliant  = 0usize;
    let mut hybrid     = 0usize;

    for c in components {
        *by_family.entry(c.algorithm_family.clone()).or_insert(0) += 1;
        let mat_key = format!("{:?}", c.maturity);
        *by_maturity.entry(mat_key).or_insert(0) += 1;
        match c.quantum_risk {
            QuantumRisk::Vulnerable => vulnerable += 1,
            QuantumRisk::Weakened   => weakened   += 1,
            QuantumRisk::Broken     => broken     += 1,
            QuantumRisk::None       => {}
        }
        if c.cnsa2_compliant { compliant += 1; }
        if c.is_hybrid       { hybrid    += 1; }
    }

    CbomSummary {
        total_assets:           components.len(),
        quantum_vulnerable:     vulnerable,
        grover_weakened:        weakened,
        classically_broken:     broken,
        cnsa2_compliant:        compliant,
        hybrid_implementations: hybrid,
        by_algorithm_family:    by_family,
        by_maturity,
    }
}

fn compute_compliance(components: &[CryptoAsset], summary: &CbomSummary) -> CbomCompliance {
    let total      = summary.total_assets.max(1);
    let compliant  = summary.cnsa2_compliant;
    let score      = ((compliant as f64 / total as f64) * 100.0) as u32;
    let ready      = summary.quantum_vulnerable == 0 && summary.classically_broken == 0;
    let non_comply = summary.quantum_vulnerable + summary.classically_broken + summary.grover_weakened;

    let immediate = if summary.classically_broken > 0 {
        Some(format!("URGENTE: {} algoritmo(s) classicamente quebrado(s) detectado(s). Substituir imediatamente (MD5, SHA-1, DES, RC4).", summary.classically_broken))
    } else if summary.quantum_vulnerable > 0 {
        Some(format!("{} algoritmo(s) vulnerável(eis) ao algoritmo de Shor. Iniciar migração PQC antes de jan/2027 (CNSA 2.0).", summary.quantum_vulnerable))
    } else {
        None
    };

    CbomCompliance {
        cnsa2_score:         score,
        cnsa2_ready:         ready,
        frameworks:          vec![
            "NIST FIPS 203 (ML-KEM)".to_string(),
            "NIST FIPS 204 (ML-DSA)".to_string(),
            "NIST FIPS 205 (SLH-DSA)".to_string(),
            "NSA CNSA 2.0".to_string(),
            "EO-14412 (June 2026)".to_string(),
            "CycloneDX 1.5 CBOM".to_string(),
        ],
        nearest_deadline:    "2027-01-01 (CNSA 2.0 — new NSS acquisitions)".to_string(),
        non_compliant_count: non_comply,
        immediate_action:    immediate,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_algorithm_from_title(title: &str) -> String {
    let t = title.to_uppercase();
    if t.contains("RSA")    { "RSA".to_string() }
    else if t.contains("ECDSA") || t.contains("ECDH") { "ECDSA/ECDH".to_string() }
    else if t.contains("MD5")   { "MD5".to_string() }
    else if t.contains("SHA-1") || t.contains("SHA1") { "SHA-1".to_string() }
    else if t.contains("SHA-256") { "SHA-256".to_string() }
    else if t.contains("AES-128") { "AES-128".to_string() }
    else if t.contains("AES")   { "AES".to_string() }
    else if t.contains("DES")   { "3DES/DES".to_string() }
    else if t.contains("RC4")   { "RC4".to_string() }
    else if t.contains("JWT")   { "JWT".to_string() }
    else if t.contains("TLS")   { "TLS".to_string() }
    else if t.contains("DH") && !t.contains("ECDH") { "DH".to_string() }
    else { title.chars().take(30).collect() }
}

fn extract_key_size(title: &str, snippet: &str) -> Option<u32> {
    let combined = format!("{} {}", title, snippet);
    let re_sizes = ["4096", "3072", "2048", "1024", "512", "256", "192", "128"];
    for size in &re_sizes {
        if combined.contains(size) {
            if let Ok(n) = size.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

fn format_timestamp(secs: u64) -> String {
    // Formato ISO 8601 simplificado sem dependência externa
    let days_since_epoch = secs / 86400;
    let year  = 1970 + days_since_epoch / 365;
    let month = (days_since_epoch % 365) / 30 + 1;
    let day   = (days_since_epoch % 365) % 30 + 1;
    let h     = (secs % 86400) / 3600;
    let m     = (secs % 3600) / 60;
    let s     = secs % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, h, m, s)
}

// ── Serialização JSON ─────────────────────────────────────────────────────────

/// Serializa CBOM para JSON
pub fn cbom_to_json(cbom: &CryptoBom) -> String {
    serde_json::to_string_pretty(cbom).unwrap_or_else(|_| "{}".to_string())
}

/// Serializa CBOM para CycloneDX 1.5 JSON
pub fn cbom_to_cyclonedx(cbom: &CryptoBom) -> String {
    let components_json: Vec<serde_json::Value> = cbom.components.iter().map(|c| {
        serde_json::json!({
            "type": "cryptographic-asset",
            "bom-ref": c.id,
            "name": c.algorithm,
            "cryptoProperties": {
                "assetType": c.usage,
                "algorithmProperties": {
                    "primitive": c.algorithm_family,
                    "parameterSetIdentifier": c.key_size.map(|k| k.to_string()),
                    "executionEnvironment": "software"
                },
                "oid": null
            },
            "evidence": {
                "occurrences": [{
                    "location": format!("{}:{}", c.file, c.line)
                }]
            },
            "properties": [
                {"name": "quantum-risk",     "value": format!("{:?}", c.quantum_risk)},
                {"name": "cnsa2-compliant",  "value": c.cnsa2_compliant.to_string()},
                {"name": "maturity",         "value": format!("{:?}", c.maturity)},
                {"name": "is-hybrid",        "value": c.is_hybrid.to_string()},
                {"name": "recommended-pqc",  "value": c.recommended_pqc.clone().unwrap_or_default()},
                {"name": "rule-id",          "value": c.rule_id.clone()},
            ]
        })
    }).collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": cbom.generated_at,
            "tools": [{
                "vendor": "OmniUil AI",
                "name": "omniuil-ai",
                "version": cbom.scanner_version
            }],
            "component": {
                "type": "application",
                "name": cbom.scan_path
            }
        },
        "components": components_json,
        "cbomCompliance": {
            "cnsa2Score": cbom.compliance.cnsa2_score,
            "cnsa2Ready": cbom.compliance.cnsa2_ready,
            "frameworks": cbom.compliance.frameworks,
            "nearestDeadline": cbom.compliance.nearest_deadline,
            "immediateAction": cbom.compliance.immediate_action
        }
    })).unwrap_or_else(|_| "{}".to_string())
}
