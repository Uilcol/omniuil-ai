//! OmniUil AI v6.0 — Entropy-based Secret Detection
//! Detecta segredos hardcoded usando entropia + padrões heurísticos.
//!
//! Como funciona (não usa machine learning):
//! - Entropia de Shannon para destacar strings de alta aleatoriedade
//! - Padrões de formato conhecido (prefixos de provedores)
//! - Score de confiança aditivo, com pesos definidos manualmente
//!
//! Detecta:
//! - API keys (AWS, GCP, GitHub, Stripe, Twilio, SendGrid, etc.)
//! - Tokens JWT, OAuth, Bearer
//! - Chaves privadas PEM
//! - Segredos de alta entropia em variáveis com nomes suspeitos
//! - Senhas hardcoded
//! - Hashes de senha que não deveriam estar no código
//!
//! Zero unsafe code. Zero I/O de rede. Determinístico.

use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Tipos ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub file:           String,
    pub line:           u32,
    pub secret_type:    String,
    pub severity:       String,
    pub confidence:     f32,        // 0.0-1.0
    pub evidence:       String,     // trecho redacted
    pub rule_id:        String,
    pub description:    String,
    pub recommendation: String,
    pub entropy:        f32,        // entropia de Shannon
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretReport {
    pub file:           String,
    pub findings:       Vec<SecretFinding>,
    pub files_scanned:  usize,
    pub summary:        String,
}

// ── Padrões regex de segredos conhecidos ─────────────────────────────────────

struct SecretPattern {
    name:        &'static str,
    rule_id:     &'static str,
    severity:    &'static str,
    prefix:      Option<&'static str>,   // prefixo fixo do segredo
    min_len:     usize,
    max_len:     usize,
    charset:     CharSet,
    min_entropy: f32,
    description: &'static str,
    recommendation: &'static str,
}

#[derive(PartialEq)]
enum CharSet {
    AlphaNum,
    AlphaNumHyphen,
    Hex,
    Base64,
    Any,
}

const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "AWS Access Key ID", rule_id: "QSC-SEC-001", severity: "CRITICAL",
        prefix: Some("AKIA"), min_len: 20, max_len: 20,
        charset: CharSet::AlphaNum, min_entropy: 3.5,
        description: "AWS Access Key ID detectada. Credencial de acesso AWS hardcoded.",
        recommendation: "Revogue imediatamente em AWS IAM. Use variáveis de ambiente ou AWS Secrets Manager.",
    },
    SecretPattern {
        name: "AWS Secret Access Key", rule_id: "QSC-SEC-002", severity: "CRITICAL",
        prefix: None, min_len: 40, max_len: 40,
        charset: CharSet::AlphaNumHyphen, min_entropy: 4.5,
        description: "Possível AWS Secret Access Key detectada por entropia e comprimento.",
        recommendation: "Revogue e use AWS Secrets Manager ou variáveis de ambiente.",
    },
    SecretPattern {
        name: "GitHub Personal Access Token", rule_id: "QSC-SEC-003", severity: "CRITICAL",
        prefix: Some("ghp_"), min_len: 36, max_len: 40,
        charset: CharSet::AlphaNum, min_entropy: 4.0,
        description: "GitHub Personal Access Token detectado.",
        recommendation: "Revogue em github.com/settings/tokens. Nunca commite tokens no código.",
    },
    SecretPattern {
        name: "GitHub OAuth Token", rule_id: "QSC-SEC-004", severity: "CRITICAL",
        prefix: Some("gho_"), min_len: 36, max_len: 40,
        charset: CharSet::AlphaNum, min_entropy: 4.0,
        description: "GitHub OAuth Token detectado.",
        recommendation: "Revogue imediatamente. Use variáveis de ambiente.",
    },
    SecretPattern {
        name: "Stripe Secret Key", rule_id: "QSC-SEC-005", severity: "CRITICAL",
        prefix: Some("sk_live_"), min_len: 24, max_len: 64,
        charset: CharSet::AlphaNum, min_entropy: 4.0,
        description: "Stripe Secret Key de produção detectada.",
        recommendation: "Revogue em dashboard.stripe.com. Use variáveis de ambiente.",
    },
    SecretPattern {
        name: "Stripe Test Key", rule_id: "QSC-SEC-006", severity: "HIGH",
        prefix: Some("sk_test_"), min_len: 24, max_len: 64,
        charset: CharSet::AlphaNum, min_entropy: 4.0,
        description: "Stripe Test Secret Key detectada.",
        recommendation: "Mova para variável de ambiente mesmo em ambiente de teste.",
    },
    SecretPattern {
        name: "Generic API Key (high entropy)", rule_id: "QSC-SEC-007", severity: "HIGH",
        prefix: None, min_len: 32, max_len: 64,
        charset: CharSet::AlphaNumHyphen, min_entropy: 4.8,
        description: "String de alta entropia em contexto de chave/segredo.",
        recommendation: "Mova para variável de ambiente ou gerenciador de segredos.",
    },
    SecretPattern {
        name: "JWT Token", rule_id: "QSC-SEC-008", severity: "HIGH",
        prefix: Some("eyJ"), min_len: 100, max_len: 2000,
        charset: CharSet::Base64, min_entropy: 4.0,
        description: "Token JWT hardcoded. JWTs contêm claims e potencialmente informações sensíveis.",
        recommendation: "Nunca hardcode JWTs. Tokens devem ser gerados dinamicamente.",
    },
    SecretPattern {
        name: "Private Key (PEM)", rule_id: "QSC-SEC-009", severity: "CRITICAL",
        prefix: Some("-----BEGIN"), min_len: 100, max_len: 10000,
        charset: CharSet::Any, min_entropy: 3.0,
        description: "Chave privada PEM detectada no código-fonte.",
        recommendation: "URGENTE: Revogue e gere nova chave. Use arquivos de chave fora do repositório.",
    },
    SecretPattern {
        name: "Groq API Key", rule_id: "QSC-SEC-010", severity: "CRITICAL",
        prefix: Some("gsk_"), min_len: 50, max_len: 60,
        charset: CharSet::AlphaNum, min_entropy: 4.0,
        description: "Groq API Key detectada.",
        recommendation: "Revogue em console.groq.com. Use variáveis de ambiente.",
    },
    SecretPattern {
        name: "Anthropic API Key", rule_id: "QSC-SEC-011", severity: "CRITICAL",
        prefix: Some("sk-ant-"), min_len: 90, max_len: 120,
        charset: CharSet::AlphaNumHyphen, min_entropy: 4.5,
        description: "Anthropic API Key detectada.",
        recommendation: "Revogue em console.anthropic.com. Use variáveis de ambiente.",
    },
    SecretPattern {
        name: "Google API Key", rule_id: "QSC-SEC-012", severity: "HIGH",
        prefix: Some("AIza"), min_len: 35, max_len: 40,
        charset: CharSet::AlphaNumHyphen, min_entropy: 4.0,
        description: "Google API Key detectada.",
        recommendation: "Revogue no Google Cloud Console. Restrinja por IP e API.",
    },
    SecretPattern {
        name: "Slack Bot Token", rule_id: "QSC-SEC-013", severity: "HIGH",
        prefix: Some("xoxb-"), min_len: 50, max_len: 80,
        charset: CharSet::AlphaNumHyphen, min_entropy: 4.0,
        description: "Slack Bot Token detectado.",
        recommendation: "Revogue em api.slack.com/apps. Use variáveis de ambiente.",
    },
    SecretPattern {
        name: "High-entropy password variable", rule_id: "QSC-SEC-014", severity: "MEDIUM",
        prefix: None, min_len: 12, max_len: 128,
        charset: CharSet::Any, min_entropy: 3.8,
        description: "Possível senha hardcoded em variável com nome suspeito.",
        recommendation: "Use gerenciador de segredos. Nunca hardcode senhas.",
    },
];

// ── Nomes de variáveis suspeitos ──────────────────────────────────────────────
const SUSPICIOUS_VAR_NAMES: &[&str] = &[
    "password", "passwd", "secret", "api_key", "apikey", "auth_key",
    "token", "private_key", "access_key", "secret_key", "credentials",
    "auth_token", "bearer", "api_secret", "client_secret", "webhook_secret",
    "encryption_key", "signing_key", "jwt_secret", "database_password",
    "db_password", "redis_password", "mongo_password", "smtp_password",
    "senha", "segredo", "chave", "credencial",
];

// ── Cálculo de entropia de Shannon ────────────────────────────────────────────

/// Calcula a entropia de Shannon de uma string
/// Alta entropia (> 4.5) indica string gerada aleatoriamente (possível segredo)
pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() { return 0.0; }

    let len = s.len() as f32;
    let mut freq = [0u32; 256];

    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0f32;
    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Verifica se a string pertence ao charset esperado
fn matches_charset(s: &str, charset: &CharSet) -> bool {
    match charset {
        CharSet::AlphaNum => s.chars().all(|c| c.is_alphanumeric()),
        CharSet::AlphaNumHyphen => s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
        CharSet::Hex => s.chars().all(|c| c.is_ascii_hexdigit()),
        CharSet::Base64 => s.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'),
        CharSet::Any => true,
    }
}

/// Redacta o valor do segredo para exibição segura (seguro para UTF-8)
fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    let prefix_len = (n / 4).min(8);
    let suffix_len = (n / 8).min(4);
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[n - suffix_len..].iter().collect();
    format!("{}{}{}", prefix, "*".repeat(n - prefix_len - suffix_len), suffix)
}

// ── Detecção ─────────────────────────────────────────────────────────────────

/// Analisa uma linha e retorna findings de segredos
fn detect_secrets_in_line(
    line: &str,
    lineno: u32,
    file: &str,
) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let line_lower = line.to_lowercase();

    // Ignora comentários e linhas de supressão
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("//")
        || trimmed.starts_with('*') || line.contains("omniuil:ignore")
        || line.contains("nosec") || line.contains("example")
        || line.contains("placeholder") || line.contains("your_")
        || line.contains("<") && line.contains(">") {
        return findings;
    }

    // Verifica padrões com prefixo fixo
    for pattern in SECRET_PATTERNS {
        if let Some(prefix) = pattern.prefix {
            if let Some(start) = line.find(prefix) {
                // Extrai o valor após o prefixo
                let rest = &line[start..];
                let value: String = rest.chars()
                    .take_while(|&c| !matches!(c, '"' | '\'' | ' ' | '\n' | '\r' | ',' | ')' | ']' | '}'))
                    .collect();

                if value.len() >= pattern.min_len && value.len() <= pattern.max_len {
                    let entropy = shannon_entropy(&value);
                    if entropy >= pattern.min_entropy && matches_charset(&value[prefix.len()..], &pattern.charset) {
                        let confidence = calculate_confidence(&value, pattern, &line_lower);
                        if confidence >= 0.6 {
                            findings.push(SecretFinding {
                                file:        file.to_string(),
                                line:        lineno,
                                secret_type: pattern.name.to_string(),
                                severity:    pattern.severity.to_string(),
                                confidence,
                                evidence:    redact(&value),
                                rule_id:     pattern.rule_id.to_string(),
                                description: pattern.description.to_string(),
                                recommendation: pattern.recommendation.to_string(),
                                entropy,
                            });
                        }
                    }
                }
            }
        }
    }

    // Detecção genérica: variáveis com nomes suspeitos + valor de alta entropia
    let has_suspicious_name = SUSPICIOUS_VAR_NAMES.iter()
        .any(|name| line_lower.contains(name));

    if has_suspicious_name && (line.contains('=') || line.contains(':')) {
        // Extrai valores entre aspas
        let quoted_values: Vec<&str> = extract_quoted_values(line);

        for value in quoted_values {
            if value.len() < 8 { continue; }
            if !is_plausible_secret_assignment(line, value) { continue; }

            let entropy = shannon_entropy(value);

            // Ignora valores óbvios de placeholder
            let is_placeholder = value.contains("your_") || value.contains("CHANGE_ME")
                || value.contains("TODO") || value.contains("xxx")
                || value == "null" || value == "undefined"
                || value.chars().all(|c| c == '*' || c == 'x' || c == 'X');

            if is_placeholder { continue; }

            if entropy >= 3.8 && value.len() >= 12 {
                // Verifica se já detectado por padrão com prefixo
                let head: String = value.chars().take(4).collect();
                let already = findings.iter().any(|f| f.line == lineno
                    && f.evidence.starts_with(head.as_str()));
                if !already {
                    let confidence = (entropy - 3.0) / 2.0;
                    let confidence = confidence.min(0.95).max(0.0);
                    findings.push(SecretFinding {
                        file:        file.to_string(),
                        line:        lineno,
                        secret_type: "High-entropy value in secret variable".to_string(),
                        severity:    if entropy > 4.5 { "HIGH" } else { "MEDIUM" }.to_string(),
                        confidence,
                        evidence:    redact(value),
                        rule_id:     "QSC-SEC-014".to_string(),
                        description: format!("Valor de alta entropia ({:.2} bits) em variável suspeita.", entropy),
                        recommendation: SECRET_PATTERNS.last().unwrap().recommendation.to_string(),
                        entropy,
                    });
                }
            }
        }
    }

    findings
}

/// Extrai valores entre aspas simples e duplas (seguro para UTF-8)
fn extract_quoted_values(line: &str) -> Vec<&str> {
    let mut values = Vec::new();
    let mut open: Option<(char, usize)> = None;
    for (idx, ch) in line.char_indices() {
        match open {
            None => {
                if ch == '"' || ch == '\u{27}' {
                    open = Some((ch, idx + ch.len_utf8()));
                }
            }
            Some((q, start)) => {
                if ch == q {
                    values.push(&line[start..idx]);
                    open = None;
                }
            }
        }
    }
    values
}

/// Calcula score de confiança combinando features
fn calculate_confidence(value: &str, pattern: &SecretPattern, line_lower: &str) -> f32 {
    let mut score = 0.5f32;

    // Feature 1: entropia
    let entropy = shannon_entropy(value);
    if entropy >= pattern.min_entropy + 1.0 { score += 0.2; }
    else if entropy >= pattern.min_entropy { score += 0.1; }

    // Feature 2: comprimento no range esperado
    let len = value.len();
    let mid = (pattern.min_len + pattern.max_len) / 2;
    if len >= pattern.min_len && len <= pattern.max_len {
        score += 0.15;
        if (len as i64 - mid as i64).abs() < 5 { score += 0.05; }
    }

    // Feature 3: contexto na linha (nome de variável suspeito)
    if SUSPICIOUS_VAR_NAMES.iter().any(|n| line_lower.contains(n)) {
        score += 0.1;
    }

    // Feature 4: linha de atribuição (não em comentário)
    if line_lower.contains(" = ") || line_lower.contains(": ") {
        score += 0.05;
    }

    score.min(0.99)
}

// ── Ponto de entrada público ──────────────────────────────────────────────────

/// Analisa um arquivo em busca de segredos
pub fn detect_secrets_in_file(path: &Path, content: &str) -> Vec<SecretFinding> {
    let path_str = path.display().to_string();
    let mut findings = Vec::new();

    // Ignora arquivos binários e muito grandes
    if content.len() > 1_000_000 { return findings; }
    if content.bytes().take(1000).filter(|&b| b == 0).count() > 10 {
        return findings; // provavelmente binário
    }

    for (lineno, line) in content.lines().enumerate() {
        let lineno = (lineno + 1) as u32;
        let mut line_findings = detect_secrets_in_line(line, lineno, &path_str);
        findings.append(&mut line_findings);
    }

    // Remove duplicatas por linha e tipo
    findings.dedup_by(|a, b| a.line == b.line && a.rule_id == b.rule_id);
    findings
}

/// Analisa múltiplos arquivos
pub fn detect_secrets_in_directory(dir: &Path) -> Vec<SecretReport> {
    let mut reports = Vec::new();
    let extensions = ["py","java","go","js","ts","cs","rs","rb","php",
                      "yaml","yml","json","toml","env","sh","bash","conf","config","xml"];

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() { Ok(t) => t, Err(_) => continue };
            if ft.is_symlink() { continue; }
            if ft.is_dir() {
                let dname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(dname, ".git" | "node_modules" | "target" | "vendor" | ".venv" | "__pycache__") { continue; }
                reports.extend(detect_secrets_in_directory(&path));
            } else {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Também verifica arquivos .env e similares sem extensão específica
                let is_relevant = extensions.contains(&ext)
                    || name.starts_with(".env")
                    || name == "Dockerfile"
                    || name.ends_with(".conf");

                if is_relevant {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let findings = detect_secrets_in_file(&path, &content);
                        let n = findings.len();
                        reports.push(SecretReport {
                            file:          path.display().to_string(),
                            files_scanned: 1,
                            summary:       format!("{} segredo(s) detectado(s)", n),
                            findings,
                        });
                    }
                }
            }
        }
    }
    reports
}

pub fn secrets_to_json(reports: &[SecretReport]) -> String {
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    let critical: usize = reports.iter().flat_map(|r| &r.findings)
        .filter(|f| f.severity == "CRITICAL").count();
    serde_json::to_string_pretty(&serde_json::json!({
        "analysis_type":   "secret_detection",
        "engine":          "entropy+pattern (heuristic, no machine learning)",
        "total_files":     reports.iter().map(|r| r.files_scanned).sum::<usize>(),
        "total_findings":  total,
        "critical":        critical,
        "reports":         reports,
    })).unwrap_or_else(|_| "{}".to_string())
}

pub fn format_secrets_report(reports: &[SecretReport]) -> String {
    let mut out = String::new();
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    out.push_str("╔══ OmniUil AI v6.0 — Entropy Secret Detection ══╗\n");
    out.push_str(&format!("  Arquivos: {} | Segredos: {}\n", reports.len(), total));
    out.push_str("╚════════════════════════════════════════════╝\n\n");
    for rep in reports {
        for f in &rep.findings {
            out.push_str(&format!(
                "  [{}] {} (confiança: {:.0}%, entropia: {:.2})\n  {}:{}\n  Redacted: {}\n  💡 {}\n\n",
                f.severity, f.secret_type, f.confidence*100.0, f.entropy,
                f.file, f.line, f.evidence, f.recommendation
            ));
        }
    }
    if total == 0 { out.push_str("  ✅ Nenhum segredo detectado.\n"); }
    out
}

/// Filtro estrutural da regra genérica (QSC-SEC-014): reduz falsos positivos.
/// Exige nome suspeito no LADO ESQUERDO da atribuição e valor com cara de segredo,
/// não de código, prosa, URL ou referência a variável de ambiente.
fn is_plausible_secret_assignment(line: &str, value: &str) -> bool {
    let op = match line.find(|c: char| c == '=' || c == ':') { Some(i) => i, None => return false };
    let key = line[..op].to_lowercase();
    if !SUSPICIOUS_VAR_NAMES.iter().any(|n| key.contains(n)) { return false; }
    let rest = &line[op..];
    if rest.contains("environ") || rest.contains("getenv") || rest.contains("process.env") { return false; }
    let value_pos = match line.find(value) { Some(i) => i, None => return false };
    if value_pos < op { return false; }
    if value.chars().any(|c| c.is_whitespace() || matches!(c, '(' | ')' | '{' | '}' | '[' | ']')) { return false; }
    if value.starts_with('$') || value.contains("://") || value.contains("::") || value.contains("->") { return false; }
    true
}
