//! # Análise de Taint — Absorção do OmniUil AI
//!
//! Rastreia o fluxo de dados externos (variáveis contaminadas) até
//! operações criptográficas inseguras — detectando ataques como:
//!
//! - **Algorithm Injection**: `Cipher.getInstance(user_input)` → atacante escolhe o algoritmo
//! - **Key Injection**: `RSA.generate(os.getenv("KEY_SIZE"))` → tamanho de chave controlável
//! - **JWT Algorithm Confusion**: `jwt.sign(data, request.algorithm)` → downgrade para "none"
//!
//! ## Algoritmo (3 passos)
//!
//! ```text
//! Passo 1 — Fontes de taint:
//!   env::var("X") → let algo = ...  ← variável "algo" está contaminada
//!
//! Passo 2 — Propagação:
//!   let cipher_algo = algo.trim()   ← "cipher_algo" também está contaminada
//!
//! Passo 3 — Sinks criptográficos:
//!   Cipher::new(cipher_algo)        ← ALERTA: dado contaminado em sink crypto
//! ```
//!
//! ## Limitações
//!
//! Esta é análise de taint inter-procedural simplificada (sem CFG completo).
//! Falsos positivos são possíveis. Confidence score é 0.8 (não 1.0) para
//! findings de taint para refletir isso.

use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ─── Tipos públicos ───────────────────────────────────────────────────────────

/// Tipo da fonte de dados externos (origem do taint).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaintSourceType {
    EnvironmentVariable,
    CommandLineArg,
    UserInput,
    FileRead,
    NetworkRequest,
    DatabaseRead,
}

impl std::fmt::Display for TaintSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvironmentVariable => write!(f, "variável de ambiente"),
            Self::CommandLineArg      => write!(f, "argumento de linha de comando"),
            Self::UserInput           => write!(f, "entrada do usuário"),
            Self::FileRead            => write!(f, "leitura de arquivo"),
            Self::NetworkRequest      => write!(f, "requisição HTTP"),
            Self::DatabaseRead        => write!(f, "leitura de banco de dados"),
        }
    }
}

/// Caminho completo de um fluxo de taint: fonte → propagação → sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    /// Linha onde o taint foi introduzido (1-indexed)
    pub source_line:  usize,
    /// Código-fonte da linha de origem
    pub source_code:  String,
    /// Tipo da fonte de dados externos
    pub source_type:  TaintSourceType,
    /// Nome da variável contaminada
    pub var_name:     String,
    /// Linha do sink criptográfico (1-indexed)
    pub sink_line:    usize,
    /// Código-fonte do sink
    pub sink_code:    String,
    /// Descrição do fluxo de taint detectado
    pub description:  String,
}

/// Finding gerado pela análise de taint (antes de converter para CryptoFinding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFinding {
    /// Arquivo analisado
    pub file:    String,
    /// Caminho completo do fluxo de taint
    pub path:    TaintPath,
    /// ID da regra ("TAINT-001")
    pub rule_id: String,
    /// Título do finding
    pub title:   String,
}

// ─── Padrões compilados (lazy — compilados uma vez na primeira chamada) ────────

lazy_static! {
    // ── Fontes de taint por linguagem ────────────────────────────────────────

    static ref TAINT_SOURCES: Vec<(Regex, TaintSourceType)> = vec![
        // ── Rust ──────────────────────────────────────────────────────────
        (Regex::new(r"(?:std::)?env::var\s*\(").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"(?:std::)?env::args\s*\(\)").unwrap(),
         TaintSourceType::CommandLineArg),
        (Regex::new(r"(?:std::io::)?stdin\s*\(\)|BufRead::lines\b").unwrap(),
         TaintSourceType::UserInput),
        (Regex::new(r"fs::read_to_string\s*\(|File::open\s*\(|read_to_string\s*\(").unwrap(),
         TaintSourceType::FileRead),
        (Regex::new(r"axum::body|hyper::body::to_bytes\s*\(|\.into_body\s*\(\)").unwrap(),
         TaintSourceType::NetworkRequest),

        // ── Python ────────────────────────────────────────────────────────
        (Regex::new(r"os\.environ\b|os\.getenv\s*\(|environ\.get\s*\(").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"sys\.argv\s*\[|argparse\.ArgumentParser").unwrap(),
         TaintSourceType::CommandLineArg),
        (Regex::new(r"\binput\s*\(|sys\.stdin\.read\s*\(").unwrap(),
         TaintSourceType::UserInput),
        (Regex::new(r"open\s*\([^)]+\)\.read|Path\s*\([^)]+\)\.read_text\s*\(").unwrap(),
         TaintSourceType::FileRead),
        (Regex::new(r"request\.json\b|request\.form\b|request\.data\b|request\.args\b|request\.get_json\s*\(|flask\.request\b").unwrap(),
         TaintSourceType::NetworkRequest),

        // ── Java ──────────────────────────────────────────────────────────
        (Regex::new(r"System\.getenv\s*\(|ProcessBuilder\b").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"\bargs\s*\[\s*\d+\s*\]").unwrap(),
         TaintSourceType::CommandLineArg),
        (Regex::new(r"new\s+Scanner\s*\(\s*System\.in|new\s+BufferedReader\s*\(\s*new\s+InputStreamReader").unwrap(),
         TaintSourceType::UserInput),
        (Regex::new(r"request\.getParameter\s*\(|request\.getBody\s*\(|httpRequest\.getHeader\s*\(").unwrap(),
         TaintSourceType::NetworkRequest),
        (Regex::new(r"new\s+FileReader\s*\(|Files\.readAllLines\s*\(|Files\.readString\s*\(").unwrap(),
         TaintSourceType::FileRead),
        (Regex::new(r"ResultSet\b|\.getString\s*\(|\.executeQuery\s*\(").unwrap(),
         TaintSourceType::DatabaseRead),

        // ── C# ────────────────────────────────────────────────────────────
        (Regex::new(r"Environment\.GetEnvironmentVariable\s*\(").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"Console\.ReadLine\s*\(\)|args\s*\[\s*\d+\s*\]").unwrap(),
         TaintSourceType::UserInput),
        (Regex::new(r"Request\.Form\s*\[|Request\.QueryString\s*\[|Request\.Body\b|context\.Request\b").unwrap(),
         TaintSourceType::NetworkRequest),
        (Regex::new(r"File\.ReadAllText\s*\(|File\.ReadAllLines\s*\(|new\s+StreamReader\s*\(").unwrap(),
         TaintSourceType::FileRead),
        (Regex::new(r"SqlDataReader\b|\.ExecuteReader\s*\(|\.ExecuteScalar\s*\(").unwrap(),
         TaintSourceType::DatabaseRead),

        // ── Go ────────────────────────────────────────────────────────────
        (Regex::new(r"os\.Getenv\s*\(|os\.LookupEnv\s*\(").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"os\.Args\s*\[|flag\.String\b|flag\.Parse\s*\(").unwrap(),
         TaintSourceType::CommandLineArg),
        (Regex::new(r"r\.Body\b|r\.FormValue\s*\(|io\.ReadAll\s*\(r\.Body|http\.Request\b").unwrap(),
         TaintSourceType::NetworkRequest),
        (Regex::new(r"os\.ReadFile\s*\(|ioutil\.ReadFile\s*\(|os\.Open\s*\(").unwrap(),
         TaintSourceType::FileRead),

        // ── JavaScript / TypeScript ───────────────────────────────────────
        (Regex::new(r"process\.env\.|process\.env\[").unwrap(),
         TaintSourceType::EnvironmentVariable),
        (Regex::new(r"process\.argv\s*\[").unwrap(),
         TaintSourceType::CommandLineArg),
        (Regex::new(r"req\.body\b|req\.query\b|req\.params\b|request\.body\b|ctx\.request\.body\b").unwrap(),
         TaintSourceType::NetworkRequest),
        (Regex::new(r"fs\.readFileSync\s*\(|fs\.readFile\s*\(|readFileSync\s*\(").unwrap(),
         TaintSourceType::FileRead),
    ];

    // ── Sinks criptográficos — onde taint é perigoso ─────────────────────────

    static ref CRYPTO_SINKS: Vec<Regex> = vec![
        // Algoritmos assimétricos vulneráveis
        Regex::new(r"(?i)\bRSA\b\.new|RSA\.generate|rsa\.newkeys|rsa_generate|KeyPairGenerator\.getInstance").unwrap(),
        Regex::new(r"(?i)\bECDSA\b|\.ECDH\b|ec_key_new|ECC\.generate|ecdsa\.SigningKey").unwrap(),
        Regex::new(r"(?i)\bDiffieHellman\b|DHE?\.new|dh_new\s*\(|DH_generate").unwrap(),
        // Hash fraco
        Regex::new(r#"(?i)Md5::new\s*\(|hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*['"]MD5|MD5CryptoServiceProvider|md5\.New\s*\(|crypto\.createHash\s*\(\s*['"]md5"#).unwrap(),
        Regex::new(r#"(?i)Sha1::new\s*\(|hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*['"]SHA-?1|SHA1CryptoServiceProvider|sha1\.New\s*\(|crypto\.createHash\s*\(\s*['"]sha1"#).unwrap(),
        // JWT inseguro
        Regex::new(r#"(?i)jwt\.sign\s*\(|jsonwebtoken\.sign\s*\(|JWT\.encode\s*\(|jwt_encode\s*\(|JwtSecurityToken\s*\("#).unwrap(),
        Regex::new(r#"(?i)"alg"\s*:\s*|algorithm\s*=\s*|algorithm\s*:\s*"#).unwrap(),
        // Inicialização de cipher
        Regex::new(r"(?i)Cipher\.getInstance\s*\(|AES\.new\s*\(|createCipher(?:iv)?\s*\(|new\s+AesCryptoServiceProvider\s*\(").unwrap(),
        Regex::new(r"(?i)DES(?:ede)?\.new\s*\(|DESCryptoServiceProvider|TripleDES\.new\s*\(|TripleDESCryptoServiceProvider").unwrap(),
        // Geração de chaves com tamanho variável
        Regex::new(r"(?i)rsa\.generate\s*\(|KeyPairGenerator\b|RSA\.generate_private_key\s*\(|rsa::RsaPrivateKey::new\s*\(").unwrap(),
    ];

    // ── Padrões de extração de nome de variável por linguagem ────────────────

    static ref ASSIGN_PATTERNS: Vec<Regex> = vec![
        // Rust: let x = ..., let mut x = ..., let x: T = ...
        Regex::new(r"^\s*let\s+(?:mut\s+)?(\w+)(?:\s*:\s*[^=]+)?\s*=").unwrap(),
        // Go: x := ..., var x = ...
        Regex::new(r"^\s*(?:var\s+)?(\w+)\s*:=").unwrap(),
        // Python / JS / TS: x = ...
        Regex::new(r"^\s*(\w+)\s*=[^=]").unwrap(),
        // Java / C#: Type x = ..., var x = ..., final Type x = ...
        Regex::new(r"^\s*(?:final\s+|readonly\s+|const\s+)?(?:var\s+|[A-Z]\w*(?:<[^>]*>)?\s+)(\w+)\s*=").unwrap(),
        // TypeScript const/let/var: const x = ..., let x = ...
        Regex::new(r"^\s*(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=").unwrap(),
    ];

    // Palavras-chave que nunca são nomes de variáveis
    static ref KEYWORDS: std::collections::HashSet<&'static str> = {
        let mut s = std::collections::HashSet::new();
        for kw in &[
            "if", "else", "while", "for", "return", "new", "true", "false",
            "null", "None", "let", "const", "var", "class", "fn", "func",
            "def", "import", "from", "static", "public", "private", "protected",
            "self", "this", "super", "throw", "catch", "try", "finally",
            "break", "continue", "switch", "case", "default", "yield",
        ] {
            s.insert(*kw);
        }
        s
    };
}

// ─── Analisador de taint ──────────────────────────────────────────────────────

/// Analisador de fluxo de dados contaminados.
/// Stateless — crie uma instância e reutilize para múltiplos arquivos.
pub struct TaintAnalyzer;

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analisa todas as linhas de um arquivo e retorna findings de taint.
    ///
    /// # Parâmetros
    /// - `lines`: todas as linhas do arquivo (como slice de &str)
    /// - `file`: caminho do arquivo (para identificação no finding)
    pub fn analyze(&self, lines: &[&str], file: &str) -> Vec<TaintFinding> {
        let mut findings = Vec::new();

        // ── Passo 1: Identificar fontes de taint e extrair variáveis ─────────
        // tainted: { var_name → (line_num, source_type, source_code) }
        let mut tainted: HashMap<String, (usize, TaintSourceType, String)> = HashMap::new();

        for (i, &line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if self.is_comment(trimmed) {
                continue;
            }

            for (src_re, src_type) in TAINT_SOURCES.iter() {
                if !src_re.is_match(line) {
                    continue;
                }

                // Tenta extrair variável desta linha
                if let Some(var) = self.extract_var_name(line) {
                    tainted.entry(var)
                        .or_insert_with(|| (i, src_type.clone(), trimmed.to_string()));
                }

                // Tenta extrair variável da PRÓXIMA linha (atribuição multi-linha)
                if i + 1 < lines.len() {
                    let next = lines[i + 1];
                    if let Some(var) = self.extract_var_name(next) {
                        tainted.entry(var)
                            .or_insert_with(|| (i, src_type.clone(), trimmed.to_string()));
                    }
                }

                // Tenta extrair variável da linha ANTERIOR (padrão comum em Go)
                if i > 0 {
                    let prev = lines[i - 1];
                    if let Some(var) = self.extract_var_name(prev) {
                        tainted.entry(var)
                            .or_insert_with(|| (i, src_type.clone(), trimmed.to_string()));
                    }
                }
            }
        }

        if tainted.is_empty() {
            return findings;
        }

        // ── Passo 2: Propagar taint através de atribuições ────────────────────
        // Se: let x = tainted_var.method(), então x também está contaminado
        let mut propagated = tainted.clone();

        for (i, &line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if self.is_comment(trimmed) {
                continue;
            }

            let new_var = match self.extract_var_name(line) {
                Some(v) => v,
                None    => continue,
            };

            // Verifica se alguma variável tainted aparece no RHS desta atribuição
            for (tainted_var, (src_line, src_type, src_code)) in &tainted {
                if tainted_var.len() < 2 || new_var == *tainted_var {
                    continue;
                }

                // Busca a variável como palavra inteira no restante da linha
                let after_eq = self.rhs_of_assignment(line).unwrap_or(line);
                if self.contains_word(after_eq, tainted_var) {
                    propagated.entry(new_var.clone())
                        .or_insert_with(|| {
                            (
                                *src_line,
                                src_type.clone(),
                                src_code.clone(),
                            )
                        });
                }
                let _ = i; // satisfaz borrow checker em versões mais antigas
            }
        }

        // ── Passo 3: Detectar taint em sinks criptográficos ──────────────────
        for (i, &line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if self.is_comment(trimmed) {
                continue;
            }

            // Verifica se esta linha contém um sink criptográfico
            let is_sink = CRYPTO_SINKS.iter().any(|re| re.is_match(line));
            if !is_sink {
                continue;
            }

            // Verifica se alguma variável contaminada aparece nesta linha
            for (tainted_var, (src_line, src_type, src_code)) in &propagated {
                if tainted_var.len() < 2 {
                    continue;
                }

                if !self.contains_word(line, tainted_var) {
                    continue;
                }

                let snippet_owned: String;
                let snippet = if trimmed.chars().count() > 120 {
                    snippet_owned = trimmed.chars().take(120).collect();
                    snippet_owned.as_str()
                } else {
                    trimmed
                };

                let description = format!(
                    "A variável '{}' recebe dados de {} (linha {}) e é usada \
                     em operação criptográfica (linha {}). Dados externos \
                     controlando parâmetros de criptografia podem permitir \
                     ataques de downgrade, confusão de algoritmo ou injeção de chave.",
                    tainted_var,
                    src_type,
                    src_line + 1,
                    i + 1
                );

                findings.push(TaintFinding {
                    file: file.to_string(),
                    path: TaintPath {
                        source_line: src_line + 1,
                        source_code: src_code.clone(),
                        source_type: src_type.clone(),
                        var_name:    tainted_var.clone(),
                        sink_line:   i + 1,
                        sink_code:   snippet.to_string(),
                        description,
                    },
                    rule_id: "TAINT-001".to_string(),
                    title:   format!(
                        "Fluxo de taint: {} → sink criptográfico",
                        src_type
                    ),
                });
            }
        }

        // Deduplicar: mesma variável + mesmo sink → keep first
        findings.dedup_by(|a, b| {
            a.path.var_name == b.path.var_name
                && a.path.sink_line == b.path.sink_line
        });

        findings
    }

    // ── Helpers privados ──────────────────────────────────────────────────────

    /// Extrai o nome da variável sendo atribuída na linha.
    fn extract_var_name(&self, line: &str) -> Option<String> {
        for pattern in ASSIGN_PATTERNS.iter() {
            if let Some(caps) = pattern.captures(line) {
                if let Some(m) = caps.get(1) {
                    let name = m.as_str();
                    if !KEYWORDS.contains(name) && name.len() >= 2 {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }

    /// Retorna a parte à direita do operador de atribuição.
    fn rhs_of_assignment<'a>(&self, line: &'a str) -> Option<&'a str> {
        // Suporte a := (Go), = (todos), mas não == (comparação)
        if let Some(pos) = line.find(":=") {
            return Some(&line[pos + 2..]);
        }
        // Busca '=' que não seja '==' ou '!=' ou '<=' ou '>=' ou '=>'
        let bytes = line.as_bytes();
        for i in 0..bytes.len().saturating_sub(1) {
            if bytes[i] == b'=' {
                let prev = if i > 0 { bytes[i - 1] } else { 0 };
                let next = bytes[i + 1];
                if prev != b'!' && prev != b'<' && prev != b'>' && prev != b'='
                    && next != b'=' && next != b'>'
                {
                    return Some(&line[i + 1..]);
                }
            }
        }
        None
    }

    /// Verifica se `word` aparece em `text` como palavra inteira (word boundary).
    fn contains_word(&self, text: &str, word: &str) -> bool {
        // Implementação sem criar Regex dinâmico (performance)
        let mut start = 0;
        let wlen = word.len();
        while start + wlen <= text.len() {
            if let Some(pos) = text[start..].find(word) {
                let abs = start + pos;
                let before_ok = abs == 0 || !text.as_bytes()[abs - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[abs - 1] != b'_';
                let after_pos = abs + wlen;
                let after_ok  = after_pos >= text.len()
                    || (!text.as_bytes()[after_pos].is_ascii_alphanumeric()
                        && text.as_bytes()[after_pos] != b'_');
                if before_ok && after_ok {
                    return true;
                }
                start = abs + 1;
            } else {
                break;
            }
        }
        false
    }

    /// Verifica se uma linha (trimmed) é comentário.
    fn is_comment(&self, trimmed: &str) -> bool {
        trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with('*')
            || trimmed.starts_with("/*")
            || trimmed.starts_with("'''")
            || trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("--")  // SQL
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(code: &str) -> Vec<TaintFinding> {
        let lines: Vec<&str> = code.lines().collect();
        TaintAnalyzer::new().analyze(&lines, "test.rs")
    }

    #[test]
    fn test_rust_env_to_crypto_sink() {
        let code = r#"
let algo = env::var("CRYPTO_ALG").unwrap();
let cipher = Cipher::new(algo);
"#;
        let findings = analyze(code);
        assert!(!findings.is_empty(), "Deve detectar taint: env var → crypto sink");
        assert_eq!(findings[0].path.var_name, "algo");
        assert_eq!(findings[0].path.source_type, TaintSourceType::EnvironmentVariable);
    }

    #[test]
    fn test_python_request_to_jwt() {
        let code = r#"
algorithm = request.json.get("alg")
token = jwt.sign(data, algorithm)
"#;
        let findings = analyze(code);
        assert!(!findings.is_empty(), "Deve detectar taint: request → jwt.sign");
        assert_eq!(findings[0].path.var_name, "algorithm");
        assert_eq!(findings[0].path.source_type, TaintSourceType::NetworkRequest);
    }

    #[test]
    fn test_propagation() {
        let code = r#"
let raw = env::var("ALGO").unwrap();
let algo = raw.trim().to_uppercase();
let cipher = AES::new(algo);
"#;
        let findings = analyze(code);
        // Deve detectar tanto raw→cipher quanto algo→cipher
        assert!(!findings.is_empty(), "Propagação deve funcionar");
    }

    #[test]
    fn test_no_taint_in_constant_code() {
        let code = r#"
let key = [0u8; 32];
let cipher = Aes256Gcm::new(key.into());
"#;
        let findings = analyze(code);
        // Não há fonte de taint, não deve gerar findings
        assert!(
            findings.is_empty(),
            "Código sem taint não deve gerar findings: {:?}", findings
        );
    }

    #[test]
    fn test_java_system_getenv_to_keygen() {
        let code = r#"
String keySize = System.getenv("KEY_SIZE");
KeyPairGenerator.getInstance(keySize);
"#;
        let findings = analyze(code);
        assert!(!findings.is_empty(), "Java: env var → KeyPairGenerator");
    }

    #[test]
    fn test_contains_word_boundary() {
        let analyzer = TaintAnalyzer::new();
        assert!(analyzer.contains_word("let algo = cipher.new(algo)", "algo"));
        assert!(!analyzer.contains_word("let algo2 = x", "algo")); // não é palavra inteira
        assert!(analyzer.contains_word("fn(x, algo, y)", "algo"));
    }

    #[test]
    fn test_comment_lines_ignored() {
        let code = r#"
// let algo = env::var("X").unwrap();
let cipher = AES::new("AES-256"); // constante
"#;
        let findings = analyze(code);
        assert!(findings.is_empty(), "Comentários não devem gerar taint");
    }
}
