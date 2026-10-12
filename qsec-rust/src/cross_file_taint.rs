//! OmniUil AI v6.0 — Cross-File Taint Analysis
//! Detecta vulnerabilidades criptográficas que cruzam múltiplos arquivos.
//!
//! Exemplo detectado:
//!   config.py:  HASH_ALG = "md5"        ← definição (source)
//!   crypto.py:  hashlib.new(HASH_ALG)   ← uso em sink criptográfico
//!
//! Algoritmo:
//!   1. Passe 1: coleta todas as definições de variáveis com valores PQC-relevantes
//!   2. Passe 2: detecta uso dessas variáveis em sinks criptográficos
//!   3. Gera CrossFileFinding com cadeia de evidência completa
//!
//! Zero unsafe code. Zero I/O de rede. Determinístico.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Tipos ─────────────────────────────────────────────────────────────────────

/// Definição de variável com valor criptograficamente relevante
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub variable:   String,   // nome da variável
    pub value:      String,   // valor atribuído (ex: "md5", "RSA")
    pub file:       String,   // arquivo onde foi definida
    pub line:       u32,
    pub taint_type: TaintType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaintType {
    WeakHashAlgorithm,    // "md5", "sha1", "sha-1"
    WeakCipher,           // "DES", "RC4", "AES-128"
    WeakKeySize,          // "1024", "512" (para RSA/DH)
    WeakJwtAlgorithm,     // "none", "HS256" sem verificação
    HardcodedSecret,      // valor que parece segredo
    InsecureRandom,       // "Math.random", "random.random"
}

/// Sink criptográfico — onde variáveis tainted são usadas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file:      String,
    pub line:      u32,
    pub code:      String,
    pub sink_type: String,  // "hashlib.new", "Cipher.getInstance", etc.
}

/// Finding cross-file — vulnerabilidade que cruza arquivos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileFinding {
    pub id:          String,
    pub severity:    String,
    pub title:       String,
    pub description: String,
    pub source:      TaintSource,      // onde o valor perigoso foi definido
    pub sink:        TaintSink,        // onde foi usado em operação crypto
    pub taint_chain: Vec<String>,      // cadeia de propagação
    pub recommendation: String,
    pub rule_id:     String,
}

/// Resultado da análise cross-file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileTaintResult {
    pub files_analyzed:   usize,
    pub sources_found:    usize,
    pub sinks_found:      usize,
    pub cross_file_findings: Vec<CrossFileFinding>,
    pub same_file_findings:  Vec<CrossFileFinding>,
    pub summary:          String,
}

// ── Padrões de sources (definições de variáveis com valores perigosos) ─────────

/// Valores que indicam algoritmo fraco quando atribuídos a variável
const WEAK_HASH_VALUES: &[&str] = &[
    "\"md5\"", "'md5'", "\"MD5\"", "'MD5'",
    "\"sha1\"", "'sha1'", "\"SHA1\"", "'SHA1'",
    "\"sha-1\"", "'sha-1'", "\"SHA-1\"", "'SHA-1'",
    "\"sha256\"", "'sha256'",  // fraco contra Grover em contextos de segurança longa
];

const WEAK_CIPHER_VALUES: &[&str] = &[
    "\"DES\"", "'DES'", "\"3DES\"", "'3DES'",
    "\"RC4\"", "'RC4'", "\"RC2\"", "'RC2'",
    "\"AES-128\"", "'AES-128'", "\"AES128\"", "'AES128'",
    "\"Blowfish\"", "'Blowfish'",
];

const WEAK_JWT_VALUES: &[&str] = &[
    "\"none\"", "'none'", "\"HS256\"", "'HS256'",
    "\"RS256\"", "'RS256'", "\"ES256\"", "'ES256'",
];

/// Padrões de sinks — onde variáveis são usadas em operações crypto
const CRYPTO_SINKS: &[(&str, &str)] = &[
    // Python
    ("hashlib.new(",        "hashlib.new"),
    ("hashlib.md5(",        "hashlib.md5"),
    ("hashlib.sha1(",       "hashlib.sha1"),
    ("Cipher.new(",         "Cipher.new"),
    ("AES.new(",            "AES.new"),
    ("jwt.encode(",         "jwt.encode"),
    ("jwt.decode(",         "jwt.decode"),
    // Java
    ("MessageDigest.getInstance(", "MessageDigest.getInstance"),
    ("Cipher.getInstance(",        "Cipher.getInstance"),
    ("KeyPairGenerator.getInstance(", "KeyPairGenerator.getInstance"),
    ("new JwtBuilder(",            "JwtBuilder"),
    // Go
    ("md5.New(",       "md5.New"),
    ("sha1.New(",      "sha1.New"),
    ("aes.NewCipher(", "aes.NewCipher"),
    // JavaScript
    ("createHash(",    "createHash"),
    ("createCipher(",  "createCipher"),
    ("sign(",          "jwt.sign"),
    // C#
    ("MD5.Create(",    "MD5.Create"),
    ("SHA1.Create(",   "SHA1.Create"),
    ("DES.Create(",    "DES.Create"),
    ("RijndaelManaged(", "RijndaelManaged"),
];

// ── Passe 1: Coleta de sources ────────────────────────────────────────────────

/// Extrai definições de variáveis com valores criptograficamente perigosos
pub fn collect_taint_sources(file: &str, content: &str) -> Vec<TaintSource> {
    let mut sources = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let lineno = (lineno + 1) as u32;
        let trimmed = line.trim();

        // Ignora comentários
        if trimmed.starts_with('#') || trimmed.starts_with("//")
            || trimmed.starts_with('*') { continue; }

        // Detecta atribuições: VAR = "value" ou VAR: str = "value"
        let has_assignment = line.contains(" = ") || line.contains(": str =")
            || line.contains(": String =") || line.contains("const ")
            || line.contains("let ") || line.contains("var ");

        if !has_assignment { continue; }

        // Extrai nome da variável (antes do =)
        let var_name = extract_variable_name(line);
        if var_name.is_empty() { continue; }

        // Verifica se o valor é um algoritmo fraco
        for &weak_val in WEAK_HASH_VALUES {
            if line.contains(weak_val) {
                let clean_val = weak_val.trim_matches(|c| c == '"' || c == '\'');
                sources.push(TaintSource {
                    variable:   var_name.clone(),
                    value:      clean_val.to_string(),
                    file:       file.to_string(),
                    line:       lineno,
                    taint_type: TaintType::WeakHashAlgorithm,
                });
                break;
            }
        }

        for &weak_val in WEAK_CIPHER_VALUES {
            if line.contains(weak_val) {
                let clean_val = weak_val.trim_matches(|c| c == '"' || c == '\'');
                sources.push(TaintSource {
                    variable:   var_name.clone(),
                    value:      clean_val.to_string(),
                    file:       file.to_string(),
                    line:       lineno,
                    taint_type: TaintType::WeakCipher,
                });
                break;
            }
        }

        for &weak_val in WEAK_JWT_VALUES {
            if line.contains(weak_val) && (var_name.to_lowercase().contains("alg")
                || var_name.to_lowercase().contains("algorithm")
                || var_name.to_lowercase().contains("jwt")) {
                let clean_val = weak_val.trim_matches(|c| c == '"' || c == '\'');
                sources.push(TaintSource {
                    variable:   var_name.clone(),
                    value:      clean_val.to_string(),
                    file:       file.to_string(),
                    line:       lineno,
                    taint_type: TaintType::WeakJwtAlgorithm,
                });
                break;
            }
        }
    }

    sources
}

// ── Passe 2: Detecção de sinks usando variáveis tainted ───────────────────────

/// Detecta uso de variáveis tainted em sinks criptográficos
pub fn detect_taint_sinks(
    file: &str,
    content: &str,
    sources: &[TaintSource],
) -> Vec<(TaintSource, TaintSink)> {
    let mut hits = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let lineno    = (lineno + 1) as u32;
        let trimmed   = line.trim();

        // Ignora comentários e supressões
        if trimmed.starts_with('#') || trimmed.starts_with("//")
            || line.contains("omniuil:ignore") || line.contains("nosec") {
            continue;
        }

        // Verifica se a linha contém um sink criptográfico
        let sink_match = CRYPTO_SINKS.iter().find(|(pattern, _)| line.contains(pattern));
        if sink_match.is_none() { continue; }

        let (_, sink_type) = sink_match.unwrap();

        // Verifica se alguma variável tainted é usada neste sink
        for source in sources {
            // Variável usada diretamente no sink
            if line.contains(&source.variable) {
                let sink = TaintSink {
                    file:      file.to_string(),
                    line:      lineno,
                    code:      trimmed.chars().take(120).collect(),
                    sink_type: sink_type.to_string(),
                };
                hits.push((source.clone(), sink));
            }
        }
    }

    hits
}

// ── Análise completa cross-file ───────────────────────────────────────────────

/// Executa análise cross-file em múltiplos arquivos
pub fn analyze_cross_file(files: &[(String, String)]) -> CrossFileTaintResult {
    // Passe 1: coleta todos os sources de todos os arquivos
    let mut all_sources: Vec<TaintSource> = Vec::new();
    for (file, content) in files {
        let sources = collect_taint_sources(file, content);
        all_sources.extend(sources);
    }

    // Passe 2: detecta sinks em todos os arquivos usando todos os sources
    let mut cross_findings  = Vec::new();
    let mut same_findings   = Vec::new();
    let mut total_sinks     = 0usize;
    let mut finding_counter = 0usize;

    for (file, content) in files {
        let hits = detect_taint_sinks(file, content, &all_sources);
        total_sinks += hits.len();

        for (source, sink) in hits {
            finding_counter += 1;
            let is_cross_file = source.file != sink.file;

            let (severity, title, desc, rec) = classify_cross_finding(&source, &sink);

            let chain = if is_cross_file {
                vec![
                    format!("{}:{} — definição: {} = \"{}\"",
                        source.file.split('/').last().unwrap_or(&source.file),
                        source.line, source.variable, source.value),
                    format!("{}:{} — uso em sink: {}({}...)",
                        sink.file.split('/').last().unwrap_or(&sink.file),
                        sink.line, sink.sink_type, source.variable),
                ]
            } else {
                vec![
                    format!("linha {} — definição: {} = \"{}\"",
                        source.line, source.variable, source.value),
                    format!("linha {} — uso em sink: {}",
                        sink.line, sink.sink_type),
                ]
            };

            let finding = CrossFileFinding {
                id:          format!("XFILE-{:04}", finding_counter),
                severity:    severity.to_string(),
                title:       title.to_string(),
                description: desc.to_string(),
                source,
                sink,
                taint_chain: chain,
                recommendation: rec.to_string(),
                rule_id:     "QSC-XFILE-001".to_string(),
            };

            if is_cross_file {
                cross_findings.push(finding);
            } else {
                same_findings.push(finding);
            }
        }
    }

    let summary = format!(
        "Cross-file taint: {} source(s), {} sink(s), {} finding(s) cross-file, {} same-file",
        all_sources.len(), total_sinks,
        cross_findings.len(), same_findings.len()
    );

    CrossFileTaintResult {
        files_analyzed:      files.len(),
        sources_found:       all_sources.len(),
        sinks_found:         total_sinks,
        cross_file_findings: cross_findings,
        same_file_findings:  same_findings,
        summary,
    }
}

fn classify_cross_finding(
    source: &TaintSource,
    _sink: &TaintSink,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match source.taint_type {
        TaintType::WeakHashAlgorithm => (
            "HIGH",
            "Algoritmo de hash fraco propagado de variável cross-file",
            "Variável com valor de algoritmo fraco (MD5/SHA-1) definida em um arquivo e usada em operação criptográfica em outro. Vulnerabilidade invisível para scanners intra-arquivo.",
            "Substitua o valor da variável por SHA3-256 ou BLAKE2b. Considere usar constante tipada em vez de string.",
        ),
        TaintType::WeakCipher => (
            "CRITICAL",
            "Cifra fraca propagada de variável cross-file",
            "Variável com cifra vulnerável (DES/RC4/AES-128) definida em arquivo de configuração e usada em operação de criptografia em outro arquivo.",
            "Substitua por AES-256-GCM. Evite passar algoritmos como strings — use constantes tipadas.",
        ),
        TaintType::WeakJwtAlgorithm => (
            "CRITICAL",
            "Algoritmo JWT fraco propagado de variável cross-file",
            "Variável com algoritmo JWT vulnerável (none/HS256/RS256) propagada para operação de assinatura JWT em outro arquivo.",
            "Use EdDSA (Ed25519) como passo intermediário. Target: ML-DSA-65 (NIST FIPS 204).",
        ),
        TaintType::HardcodedSecret => (
            "HIGH",
            "Segredo hardcoded propagado cross-file",
            "Segredo definido em arquivo de configuração e propagado para operação criptográfica.",
            "Use variáveis de ambiente ou gerenciador de segredos (HashiCorp Vault, AWS Secrets Manager).",
        ),
        _ => (
            "MEDIUM",
            "Valor criptograficamente suspeito propagado cross-file",
            "Valor suspeito propagado entre arquivos para operação criptográfica.",
            "Revisar manualmente. Consulte NIST SP 800-131A Rev 3.",
        ),
    }
}

fn extract_variable_name(line: &str) -> String {
    // Tenta extrair nome da variável de padrões comuns:
    // PYTHON:  VAR_NAME = "value"  ou  var_name: str = "value"
    // JS/TS:   const VAR = "value"  ou  let var = "value"
    // JAVA:    String VAR = "value"
    // RUST:    let var = "value"  ou  const VAR: &str = "value"

    let trimmed = line.trim();

    // Remove qualifiers comuns
    let stripped = trimmed
        .trim_start_matches("public ")
        .trim_start_matches("private ")
        .trim_start_matches("protected ")
        .trim_start_matches("static ")
        .trim_start_matches("final ")
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("String ")
        .trim_start_matches("str ")
        .trim_start_matches("&str ");

    // Extrai até o primeiro = ou :
    let end = stripped.find(|c| c == '=' || c == ':')
        .unwrap_or(0);

    if end == 0 { return String::new(); }

    stripped[..end].trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Serializa resultado para JSON
pub fn cross_taint_to_json(result: &CrossFileTaintResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

/// Formata resultado para terminal
pub fn format_cross_taint(result: &CrossFileTaintResult) -> String {
    let mut out = String::new();
    out.push_str("╔══ OmniUil AI v6.0 — Cross-File Taint Analysis ══╗\n");
    out.push_str(&format!("  Arquivos analisados:  {}\n", result.files_analyzed));
    out.push_str(&format!("  Sources encontrados:  {}\n", result.sources_found));
    out.push_str(&format!("  Sinks encontrados:    {}\n", result.sinks_found));
    out.push_str(&format!("  Findings cross-file:  {}\n", result.cross_file_findings.len()));
    out.push_str(&format!("  Findings same-file:   {}\n", result.same_file_findings.len()));
    out.push_str("╚══════════════════════════════════════════════════╝\n\n");

    for f in &result.cross_file_findings {
        out.push_str(&format!("🔴 {} [{}] — {}\n", f.id, f.severity, f.title));
        out.push_str("   Cadeia de propagação:\n");
        for step in &f.taint_chain {
            out.push_str(&format!("     → {}\n", step));
        }
        out.push_str(&format!("   💡 {}\n\n", f.recommendation));
    }

    if result.cross_file_findings.is_empty() {
        out.push_str("✅ Nenhum finding cross-file detectado.\n");
    }
    out
}
