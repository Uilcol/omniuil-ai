//! # Crypto Scanner — Pilar 1
//!
//! Escaneia código-fonte em busca de criptografia fraca ou não preparada
//! para a era pós-quântica.
//!
//! ## Regras implementadas
//!
//! | ID       | Severidade | Detecta                                         |
//! |----------|------------|-------------------------------------------------|
//! | QSC-001  | CRITICAL   | RSA (vulnerável ao algoritmo de Shor)           |
//! | QSC-002  | CRITICAL   | ECDSA / ECDH / curvas elípticas                 |
//! | QSC-003  | CRITICAL   | Diffie-Hellman clássico                         |
//! | QSC-010  | HIGH       | MD5                                             |
//! | QSC-011  | HIGH       | SHA-1                                           |
//! | QSC-012  | HIGH       | AES-ECB (semanticamente inseguro)               |
//! | QSC-013  | HIGH       | DES / 3DES (depreciado NIST 2023)               |
//! | QSC-014  | CRITICAL   | RC4 (RFC 7465 — proibido no TLS)                |
//! | QSC-020  | CRITICAL   | JWT algoritmo "none"                            |
//! | QSC-021  | MEDIUM     | JWT HMAC simétrico (HS256/384/512)              |
//! | QSC-022  | CRITICAL   | JWT assinado com RSA (RS256/384/512)            |
//! | QSC-030  | HIGH       | Chaves / segredos hardcoded                     |
//! | QSC-040+ | HIGH       | Dependências com crypto vulnerável conhecida    |

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{ScannerError, ScannerResult};
use crate::evidence::EvidenceGraph;
use crate::languages::{apply_language_rules, detect_language, Language};
use crate::rules::RuleEngine;
use crate::taint::TaintAnalyzer;

// ─── SEVERIDADE ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::Low      => write!(f, "LOW"),
        }
    }
}

// ─── FINDING ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    pub file:           String,
    pub line:           usize,
    pub column:         usize,
    pub severity:       Severity,
    pub rule_id:        String,
    pub title:          String,
    pub description:    String,
    pub recommendation: String,
    pub code_snippet:   String,
}

// ─── REGRA ────────────────────────────────────────────────────────────────────

struct Rule {
    id:             &'static str,
    severity:       Severity,
    title:          &'static str,
    description:    &'static str,
    recommendation: &'static str,
    pattern:        Regex,
}

// ─── REGRAS COMPILADAS (lazy_static — compiladas uma vez) ─────────────────────

lazy_static! {
    static ref RULES: Vec<Rule> = vec![

        Rule {
            id: "QSC-001",
            severity: Severity::Critical,
            title: "RSA detectado",
            description: "RSA é vulnerável ao algoritmo de Shor em computadores quânticos. \
                          Dados protegidos com RSA hoje podem ser descriptografados no futuro \
                          (Harvest Now, Decrypt Later).",
            recommendation: "Migre para ML-DSA (assinaturas) ou ML-KEM (troca de chaves). \
                             Use modo híbrido durante a transição.",
            pattern: Regex::new(r"(?i)\bRSA\b|rsa_generate|RSA\.generate|rsa\.new\(|load_rsa|import_rsa").unwrap(),
        },

        Rule {
            id: "QSC-002",
            severity: Severity::Critical,
            title: "Criptografia de curva elíptica detectada",
            description: "ECDSA e ECDH são vulneráveis ao algoritmo de Shor. \
                          Curvas elípticas oferecem zero proteção contra adversários quânticos.",
            recommendation: "Use ML-DSA para assinaturas e ML-KEM para encapsulamento de chaves.",
            pattern: Regex::new(r"(?i)\bECDSA\b|\bECDH\b|ec_key_new|EC_KEY_new|\
                                 elliptic.curve|secp256k1|secp384r1|secp521r1|P-256|P-384|P-521|\
                                 prime256v1|brainpool|curve25519_donna|EllipticCurve").unwrap(),
        },

        Rule {
            id: "QSC-003",
            severity: Severity::Critical,
            title: "Diffie-Hellman clássico detectado",
            description: "DH e DHE são vulneráveis a computadores quânticos via algoritmo de Shor.",
            recommendation: "Use ML-KEM para troca de chaves pós-quântica.",
            pattern: Regex::new(r"(?i)\bDHE\b|\bDH\b.*key|DiffieHellman|dh_new\(|DH_generate_parameters").unwrap(),
        },

        Rule {
            id: "QSC-010",
            severity: Severity::High,
            title: "MD5 detectado",
            description: "MD5 é criptograficamente quebrado. Colisões podem ser geradas em segundos.",
            recommendation: "Use SHA3-256 ou BLAKE2b para hashes de segurança.",
            pattern: Regex::new(r"(?i)\bmd5\b|Md5::new|MessageDigest::md5|md5_init|MD5_Init|DigestAlgorithm::Md5").unwrap(),
        },

        Rule {
            id: "QSC-011",
            severity: Severity::High,
            title: "SHA-1 detectado",
            description: "SHA-1 está oficialmente quebrado (SHAttered attack, 2017).",
            recommendation: "Use SHA3-256. Para resistência quântica, prefira SHA3.",
            pattern: Regex::new(r"(?i)\bsha1\b|Sha1::new|MessageDigest::sha1|SHA1_Init|DigestAlgorithm::Sha1|\.sha1\(").unwrap(),
        },

        Rule {
            id: "QSC-012",
            severity: Severity::High,
            title: "AES modo ECB detectado",
            description: "AES-ECB não é semanticamente seguro — padrões no plaintext \
                          vazam para o ciphertext (Linux Penguin attack).",
            recommendation: "Use AES-256-GCM (autenticado) ou ChaCha20-Poly1305.",
            pattern: Regex::new(r"(?i)AES_ECB|MODE_ECB|Ecb<Aes|aes.*ecb|ecb.*aes|BlockMode::Ecb").unwrap(),
        },

        Rule {
            id: "QSC-013",
            severity: Severity::High,
            title: "DES / 3DES detectado",
            description: "DES tem chave de 56 bits — quebrado por força bruta. \
                          3DES foi depreciado pelo NIST em 2023.",
            recommendation: "Use AES-256-GCM.",
            pattern: Regex::new(r"(?i)\b3DES\b|\bTripleDES\b|Des::new\b|TripleDes::new|DES_set_key|des_cbc").unwrap(),
        },

        Rule {
            id: "QSC-014",
            severity: Severity::Critical,
            title: "RC4 detectado",
            description: "RC4 tem múltiplas vulnerabilidades conhecidas. \
                          Proibido no TLS (RFC 7465).",
            recommendation: "Use ChaCha20-Poly1305 ou AES-256-GCM.",
            pattern: Regex::new(r"(?i)\bRC4\b|\bARC4\b|Rc4::new|rc4_init|RC4_set_key").unwrap(),
        },

        Rule {
            id: "QSC-020",
            severity: Severity::Critical,
            title: "JWT com algoritmo 'none'",
            description: "JWT com algoritmo 'none' ignora verificação de assinatura completamente. \
                          Permite adulteração trivial do payload.",
            recommendation: "Use ML-DSA para JWTs pós-quânticos ou EdDSA no mínimo.",
            pattern: Regex::new(r#"(?i)algorithm.*"none"|alg.*"none"|"alg"\s*:\s*"none""#).unwrap(),
        },

        Rule {
            id: "QSC-021",
            severity: Severity::Medium,
            title: "JWT com HMAC simétrico",
            description: "HS256/384/512 usa segredo compartilhado — difícil de revogar, \
                          sem non-repudiation, vulnerável a brute force em chaves fracas.",
            recommendation: "Use ML-DSA ou EdDSA para JWTs com verificação de identidade.",
            pattern: Regex::new(r#"(?i)algorithm.*"HS(256|384|512)"|"alg"\s*:\s*"HS(256|384|512)""#).unwrap(),
        },

        Rule {
            id: "QSC-022",
            severity: Severity::Critical,
            title: "JWT assinado com RSA",
            description: "RS256/384/512 usa RSA — vulnerável a computadores quânticos.",
            recommendation: "Migre para ML-DSA. Durante a transição, use modo híbrido.",
            pattern: Regex::new(r#"(?i)algorithm.*"RS(256|384|512)"|"alg"\s*:\s*"RS(256|384|512)"|Algorithm::RS256|Algorithm::RS384|Algorithm::RS512"#).unwrap(),
        },

        Rule {
            id: "QSC-030",
            severity: Severity::High,
            title: "Segredo ou chave hardcoded",
            description: "Segredos no código-fonte são expostos em repositórios, \
                          logs e builds. Risco de vazamento crítico.",
            recommendation: "Use variáveis de ambiente, Vault, ou HSM para gerenciar segredos.",
            pattern: Regex::new(
                r#"(?i)(secret|private_key|api_key|password|passwd|token)\s*[=:]\s*["'][A-Za-z0-9+/=]{16,}["']"#
            ).unwrap(),
        },

        Rule {
            id: "QSC-031",
            severity: Severity::High,
            title: "Semente aleatória previsível",
            description: "Usar tempo, PID ou valores constantes como semente RNG é previsível \
                          e quebra todas as garantias criptográficas.",
            recommendation: "Use OsRng (rand_core::OsRng) ou getrandom::getrandom().",
            pattern: Regex::new(r"(?i)StdRng::seed_from_u64|SeedableRng::seed_from_u64|SmallRng|thread_rng.*seed|srand\(time").unwrap(),
        },

        Rule {
            id: "QSC-040",
            severity: Severity::High,
            title: "Uso direto de memória não zeroizada com chaves",
            description: "Chaves criptográficas em Vec<u8> ou arrays simples não são \
                          zeroizadas no Drop — ficam na memória após uso.",
            recommendation: "Use zeroize::Zeroize / ZeroizeOnDrop ou tipos como \
                             SecretBox<T> da crate secrecy.",
            pattern: Regex::new(r"(?i)let\s+\w*(key|secret|private)\w*\s*:\s*Vec<u8>|let mut\s+\w*(key|secret)\w*\s*=\s*vec!").unwrap(),
        },
    ];

    // Dependências Rust com problemas conhecidos
    static ref VULN_CRATES: HashMap<&'static str, (&'static str, Severity, &'static str, &'static str)> = {
        let mut m = HashMap::new();
        m.insert("rust-crypto",  ("QSC-050", Severity::Critical,
            "rust-crypto está abandonado desde 2016 e tem vulnerabilidades não corrigidas",
            "Use RustCrypto (aes, sha2, sha3, hmac) — crates modulares auditadas"));
        m.insert("crypto",       ("QSC-051", Severity::Critical,
            "crate 'crypto' é o mesmo pacote abandonado rust-crypto",
            "Use crates individuais do RustCrypto ecosystem"));
        m.insert("openssl",      ("QSC-052", Severity::Medium,
            "openssl bindings sem configuração explícita podem usar algoritmos legados",
            "Configure explicitamente para desabilitar RSA<4096, DH<2048, MD5, SHA1"));
        m.insert("jwt",          ("QSC-053", Severity::High,
            "crate 'jwt' tem histórico de vulnerabilidades de validação de algoritmo",
            "Use jsonwebtoken com algoritmos explícitos, ou PQC-JWT do QSEC"));
        m.insert("jsonwebtoken", ("QSC-054", Severity::Medium,
            "jsonwebtoken usa RS256/HS256 que são vulneráveis a quânticos",
            "Durante a transição, use em modo híbrido com QSEC"));
        m.insert("ring",         ("QSC-055", Severity::Medium,
            "ring não tem suporte nativo a PQC (ML-KEM/ML-DSA)",
            "Combine ring com oqs crate para operações pós-quânticas"));
        m
    };
}

// ─── SCANNER ──────────────────────────────────────────────────────────────────

/// Scanner de criptografia fraca.
///
/// Suporta arquivos `.rs`, `.py`, `.go`, `.java`, `.js`, `.ts`, `.cpp`, `.c`
/// e `Cargo.toml` / `requirements.txt` para dependências.
///
/// Integra com [`QsecConfig`] para ignore_paths, disabled_rules e padrões customizados.
///
/// ## Absorções OmniUil AI (v3.3)
///
/// - **Regras YAML**: carrega `.qsec/rules/*.yaml` via [`RuleEngine`]
/// - **Language Adapters**: regras específicas por linguagem via [`apply_language_rules`]
/// - **Taint Analysis**: rastreia fluxo fonte→sink via [`TaintAnalyzer`]
/// - **Evidence Graph**: contexto de código ao redor de cada finding via [`EvidenceGraph`]
pub struct CryptoScanner {
    /// Findings acumulados do scan atual
    pub findings: Vec<CryptoFinding>,
    /// Findings de taint analysis
    pub taint_findings: Vec<crate::taint::TaintFinding>,
    /// Grafo de evidências (contexto de código)
    pub evidence: EvidenceGraph,
    /// Motor de regras YAML customizadas
    rule_engine: RuleEngine,
    /// Analisador de taint
    taint_analyzer: TaintAnalyzer,
}

impl Default for CryptoScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoScanner {
    /// Cria um novo scanner.
    ///
    /// Tenta carregar regras YAML de `.qsec/rules/` no diretório corrente.
    /// Se o diretório não existir, continua sem regras customizadas.
    pub fn new() -> Self {
        let rules_dir = std::path::Path::new(".qsec/rules");
        let rule_engine = RuleEngine::load_from_dir(rules_dir);

        // Log de avisos de carregamento (não fatal)
        for err in rule_engine.errors() {
            eprintln!("[QSEC Rules] Aviso: {err}");
        }

        if rule_engine.rule_count() > 0 {
            eprintln!("[QSEC Rules] {} regras YAML carregadas de {}", 
                rule_engine.rule_count(), rules_dir.display());
        }

        Self {
            findings:        Vec::new(),
            taint_findings:  Vec::new(),
            evidence:        EvidenceGraph::new(),
            rule_engine,
            taint_analyzer:  TaintAnalyzer::new(),
        }
    }

    /// Cria scanner com diretório de regras YAML customizado.
    pub fn with_rules_dir(rules_dir: &Path) -> Self {
        let rule_engine = RuleEngine::load_from_dir(rules_dir);
        for err in rule_engine.errors() {
            eprintln!("[QSEC Rules] Aviso: {err}");
        }
        Self {
            findings:        Vec::new(),
            taint_findings:  Vec::new(),
            evidence:        EvidenceGraph::new(),
            rule_engine,
            taint_analyzer:  TaintAnalyzer::new(),
        }
    }

    pub fn clear(&mut self) {
        self.findings.clear();
        self.taint_findings.clear();
        self.evidence = EvidenceGraph::new();
    }

    /// Escaneia um arquivo individual.
    pub fn scan_file(&mut self, path: &Path) -> ScannerResult<Vec<CryptoFinding>> {
        self.scan_file_with_config(path, None)
    }

    /// Escaneia com configuração enterprise.
    
    fn is_suppressed(line: &str, prev_line: Option<&str>) -> bool {
        let patterns = [
            "omniuil:ignore", "omniuil: ignore",
            "qsec:ignore",    "qsec: ignore",
            "nosec",
        ];
        let check = |l: &str| patterns.iter().any(|p| l.contains(p));
        check(line) || prev_line.map_or(false, check)
    }

    pub fn scan_file_with_config(
        &mut self,
        path: &Path,
        config: Option<&crate::config::QsecConfig>,
    ) -> ScannerResult<Vec<CryptoFinding>> {
        // Verifica se path está no ignore_paths da config
        if let Some(cfg) = config {
            let path_str = path.display().to_string();
            if cfg.should_ignore(&path_str) {
                return Ok(Vec::new());
            }
        }

        let source = std::fs::read_to_string(path).map_err(|e| ScannerError::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;

        // ── Detectar linguagem (Language Adapter — OmniUil AI) ───────────────
        let language = detect_language(path);

        let mut findings = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        // ── Applica regras builtin + language-specific + YAML ────────────────
        for (lineno, &line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Ignora linhas de comentário
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            // ── Regras builtin (14 regras PQC) ────────────────────────────────
            for rule in RULES.iter() {
                if let Some(cfg) = config {
                    if !cfg.is_rule_enabled(rule.id) {
                        continue;
                    }
                }

                if let Some(m) = rule.pattern.find(line) {
                    let snippet = line.trim();
                    let snippet_owned: String;
                    let snippet = if snippet.chars().count() > 120 {
                        snippet_owned = snippet.chars().take(120).collect();
                        snippet_owned.as_str()
                    } else { snippet };

                    // Verifica anotação de supressão omniuil:ignore
                    let prev_line = if lineno > 0 { Some(lines[lineno - 1]) } else { None };
                    if Self::is_suppressed(line, prev_line) {
                        continue;
                    }

                    findings.push(CryptoFinding {
                        file:           path.display().to_string(),
                        line:           lineno + 1,
                        column:         m.start() + 1,
                        severity:       rule.severity.clone(),
                        rule_id:        rule.id.to_string(),
                        title:          rule.title.to_string(),
                        description:    rule.description.to_string(),
                        recommendation: rule.recommendation.to_string(),
                        code_snippet:   snippet.to_string(),
                    });
                }
            }

            // ── Language Adapter — regras específicas da linguagem ─────────────
            if language != Language::Unknown {
                let lang_matches = apply_language_rules(&language, line);
                for lm in lang_matches {
                    // Evita duplicata se já detectado pelas regras builtin
                    let duplicate = findings.iter().any(|f| {
                        f.line == lineno + 1 && f.rule_id.starts_with("QSC-")
                            && lm.rule_id.starts_with("QSC-")
                            && f.code_snippet.contains(&lm.matched_text)
                    });
                    if duplicate {
                        continue;
                    }

                    let snippet = line.trim();
                    let snippet_owned: String;
                    let snippet = if snippet.chars().count() > 120 {
                        snippet_owned = snippet.chars().take(120).collect();
                        snippet_owned.as_str()
                    } else { snippet };

                    let severity = match lm.severity_str {
                        "CRITICAL" => Severity::Critical,
                        "HIGH"     => Severity::High,
                        "MEDIUM"   => Severity::Medium,
                        _          => Severity::Low,
                    };

                    let prev_line = if lineno > 0 { Some(lines[lineno - 1]) } else { None };
                    if Self::is_suppressed(line, prev_line) { continue; }
                    findings.push(CryptoFinding {
                        file:           path.display().to_string(),

                        line:           lineno + 1,
                        column:         lm.column,
                        severity,
                        rule_id:        lm.rule_id.to_string(),
                        title:          lm.title.to_string(),
                        description:    lm.description.to_string(),
                        recommendation: lm.recommendation.to_string(),
                        code_snippet:   snippet.to_string(),
                    });
                }
            }

            // ── Regras YAML customizadas (RuleEngine — OmniUil AI) ────────────
            let yaml_matches = self.rule_engine.apply_to_line(
                line,
                Some(language.as_str()),
            );
            for ym in yaml_matches {
                let snippet = line.trim();
                let snippet = if snippet.len() > 120 { &snippet[..120] } else { snippet };

                let severity = match ym.severity_str.to_uppercase().as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH"     => Severity::High,
                    "MEDIUM"   => Severity::Medium,
                    _          => Severity::Low,
                };

                let prev_line = if lineno > 0 { Some(lines[lineno - 1]) } else { None };
                if Self::is_suppressed(line, prev_line) { continue; }
                findings.push(CryptoFinding {

                    file:           path.display().to_string(),
                    line:           lineno + 1,
                    column:         ym.column,
                    severity,
                    rule_id:        ym.rule_id.clone(),
                    title:          ym.title.clone(),
                    description:    ym.description.clone(),
                    recommendation: ym.recommendation.clone(),
                    code_snippet:   snippet.to_string(),
                });
            }

            // ── Padrões customizados da config enterprise ─────────────────────
            if let Some(cfg) = config {
                for custom in &cfg.scanner.extra_patterns {
                    if let Ok(re) = regex::Regex::new(&custom.pattern) {
                        if let Some(m) = re.find(line) {
                            let sev = match custom.severity.to_uppercase().as_str() {
                                "CRITICAL" => Severity::Critical,
                                "HIGH"     => Severity::High,
                                "MEDIUM"   => Severity::Medium,
                                _          => Severity::Low,
                            };
                            let snippet = line.trim();
                            let snippet = if snippet.len() > 120 { &snippet[..120] } else { snippet };
                            let prev_line = if lineno > 0 { Some(lines[lineno - 1]) } else { None };
                            if Self::is_suppressed(line, prev_line) { continue; }
                            findings.push(CryptoFinding {
                                file:           path.display().to_string(),
                                line:           lineno + 1,
                                column:         m.start() + 1,
                                severity:       sev,
                                rule_id:        custom.id.clone(),
                                title:          custom.title.clone(),
                                description:    custom.description.clone(),
                                recommendation: custom.recommendation.clone(),
                                code_snippet:   snippet.to_string(),
                            });
                        }
                    }
                }
            }
        }

        // ── Scanner especializado para Cargo.toml ─────────────────────────────
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if filename == "Cargo.toml" || filename == "Cargo.lock" {
            findings.extend(self.scan_cargo_deps(&source, path)?);
        }

        // ── Taint Analysis — OmniUil AI ───────────────────────────────────────
        // Apenas para arquivos de código (não TOML, não YAML)
        if !matches!(language, Language::Unknown)
            && filename != "Cargo.toml"
            && filename != "Cargo.lock"
        {
            let file_str = path.display().to_string();
            let taint_results = self.taint_analyzer.analyze(&lines, &file_str);

            for tf in &taint_results {
                // Adiciona ao evidence graph
                self.evidence.add_taint_finding(tf);
            }

            if !taint_results.is_empty() {
                eprintln!(
                    "[QSEC Taint] {} fluxo(s) de taint detectado(s) em {}",
                    taint_results.len(), path.display()
                );
            }

            self.taint_findings.extend(taint_results);
        }

        // ── Aplica limite de findings da config ───────────────────────────────
        if let Some(cfg) = config {
            findings.truncate(cfg.scanner.max_findings);
        }

        // ── Grafo de Evidências — para findings de scanner ────────────────────
        for f in &findings {
            self.evidence.add_scanner_finding(
                &f.file,
                f.line,
                f.column,
                &f.rule_id,
                &f.severity.to_string(),
                &f.title,
            );
        }

        self.findings.extend(findings.clone());
        Ok(findings)
    }

    /// Escaneia um diretório recursivamente.
    pub fn scan_directory(&mut self, root: &Path) -> ScannerResult<Vec<CryptoFinding>> {
        self.scan_directory_with_config(root, None)
    }

    /// Escaneia diretório com configuração enterprise.
    pub fn scan_directory_with_config(
        &mut self,
        root: &Path,
        config: Option<&crate::config::QsecConfig>,
    ) -> ScannerResult<Vec<CryptoFinding>> {
        // Extensões suportadas — usa config se disponível
        let default_exts = vec![
            "rs", "py", "go", "java", "js", "ts", "tsx", "jsx",
            "cpp", "c", "h", "cs", "kt", "swift", "rb", "toml",
        ];

        let supported_exts: Vec<&str> = if let Some(cfg) = config {
            cfg.scanner.extensions.iter().map(|s| s.as_str()).collect()
        } else {
            default_exts
        };

        const SKIP_DIRS: &[&str] = &[
            "target", ".git", "node_modules", "__pycache__",
            ".venv", "venv", "dist", "build", ".tox",
        ];

        let mut all = Vec::new();

        for entry in walkdir_simple(root) {
            let path = entry.as_path();

            // Pula diretórios builtin ignorados
            if path.components().any(|c| {
                SKIP_DIRS.contains(&c.as_os_str().to_str().unwrap_or(""))
            }) {
                continue;
            }

            // Pula caminhos da config ignore_paths
            if let Some(cfg) = config {
                if cfg.should_ignore(&path.display().to_string()) {
                    continue;
                }
            }

            let ext   = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

            if supported_exts.contains(&ext) || fname == "Cargo.toml" {
                match self.scan_file_with_config(path, config) {
                    Ok(findings) => all.extend(findings),
                    Err(e) => eprintln!("[QSEC Scanner] Warning: {e}"),
                }
            }
        }

        Ok(all)
    }

    /// Escaneia dependências de Cargo.toml.
    fn scan_cargo_deps(
        &self,
        content: &str,
        path: &Path,
    ) -> ScannerResult<Vec<CryptoFinding>> {
        let mut findings = Vec::new();

        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Extrai nome da crate: 'oqs = ...' ou '"oqs"' no formato toml
            let crate_name = if let Some(pos) = trimmed.find(" = ") {
                trimmed[..pos].trim().trim_matches('"')
            } else {
                continue;
            };

            if let Some(&(rule_id, ref sev, desc, rec)) = VULN_CRATES.get(crate_name) {
                let prev_line: Option<&str> = None; // Cargo.toml: sem acesso a linha anterior
                if Self::is_suppressed(line, prev_line) { continue; }
                findings.push(CryptoFinding {
                    file:           path.display().to_string(),
                    line:           lineno + 1,
                    column:         1,
                    severity:       sev.clone(),
                    rule_id:        rule_id.to_string(),
                    title:          format!("Dependência vulnerável: {crate_name}"),
                    description:    desc.to_string(),
                    recommendation: rec.to_string(),
                    code_snippet:   trimmed.to_string(),
                });
            }
        }

        Ok(findings)
    }

    // ── Relatórios ────────────────────────────────────────────────────────────

    /// Gera relatório em texto legível.
    pub fn report_text(&self) -> String {
        let counts = self.count_by_severity();
        let mut out = String::new();

        out.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        out.push_str("║         QSEC — Relatório de Análise Criptográfica  v3.3      ║\n");
        out.push_str("╚══════════════════════════════════════════════════════════════╝\n");
        out.push_str(&format!("  Scanner findings  : {}\n", self.findings.len()));
        out.push_str(&format!("  Taint findings    : {}\n", self.taint_findings.len()));
        out.push_str(&format!("  CRITICAL          : {}\n", counts.critical));
        out.push_str(&format!("  HIGH              : {}\n", counts.high));
        out.push_str(&format!("  MEDIUM            : {}\n", counts.medium));
        out.push_str(&format!("  LOW               : {}\n\n", counts.low));

        for sev in &[Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let group: Vec<_> = self.findings.iter().filter(|f| &f.severity == sev).collect();
            if group.is_empty() { continue; }

            out.push_str(&format!("── {} {}\n", sev, "─".repeat(52)));
            for f in group {
                out.push_str(&format!("  [{}] {}\n", f.rule_id, f.title));
                out.push_str(&format!("  📍 {}:{}:{}\n", f.file, f.line, f.column));
                out.push_str(&format!("  📝 {}\n", f.description));
                out.push_str(&format!("  ✅ {}\n", f.recommendation));
                if !f.code_snippet.is_empty() {
                    out.push_str(&format!("  🔍 {}\n", f.code_snippet));
                }
                out.push('\n');
            }
        }

        // Taint findings (OmniUil AI)
        if !self.taint_findings.is_empty() {
            out.push_str("── TAINT ANALYSIS (OmniUil AI) ───────────────────────────────\n");
            for tf in &self.taint_findings {
                out.push_str(&format!("  [{}] {}\n", tf.rule_id, tf.title));
                out.push_str(&format!("  📍 {}:{}\n", tf.file, tf.path.sink_line));
                out.push_str(&format!(
                    "  🔀 '{}' ({}) linha {} → sink linha {}\n",
                    tf.path.var_name, tf.path.source_type,
                    tf.path.source_line, tf.path.sink_line
                ));
                out.push_str(&format!("  📝 {}\n\n", tf.path.description));
            }
        }

        // Grafo de evidências (OmniUil AI)
        let has_evidence = !self.evidence.scanner_evidence.is_empty()
            || !self.evidence.taint_evidence.is_empty();
        if has_evidence {
            out.push_str(&self.evidence.render_text());
        }

        out
    }

    /// Gera relatório JSON completo (scanner + taint).
    pub fn report_json(&self) -> serde_json::Result<String> {
        use serde_json::json;
        let report = json!({
            "scanner_findings": self.findings,
            "taint_findings": self.taint_findings,
            "summary": {
                "total_scanner": self.findings.len(),
                "total_taint":   self.taint_findings.len(),
            }
        });
        serde_json::to_string_pretty(&report)
    }

    /// Conta findings por severidade.
    pub fn count_by_severity(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for f in &self.findings {
            match f.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High     => counts.high += 1,
                Severity::Medium   => counts.medium += 1,
                Severity::Low      => counts.low += 1,
            }
        }
        counts
    }

    /// Retorna `true` se há findings CRITICAL ou HIGH.
    pub fn has_blocking_findings(&self) -> bool {
        self.findings.iter().any(|f| {
            matches!(f.severity, Severity::Critical | Severity::High)
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
}

// ─── Walkdir simplificado (sem dependência extra) ─────────────────────────────

fn walkdir_simple(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    walkdir_recursive(root, &mut result);
    result
}

fn walkdir_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walkdir_recursive(&path, out);
        } else {
            out.push(path);
        }
    }
}
