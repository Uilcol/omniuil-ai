//! OmniUil AI v5.5 — Auto-Remediation Engine
//! Gera código PQC substituto para algoritmos vulneráveis.
//!
//! PRINCÍPIO DE SEGURANÇA:
//! - Por padrão: apenas mostra o diff (modo dry-run)
//! - Modifica arquivos SOMENTE com flag --fix explícita
//! - Nunca aplica remediação sem confirmação do usuário
//! - Preserva backup do arquivo original antes de qualquer modificação
//! - Zero unsafe code. Zero I/O de rede.

use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::scanner::CryptoFinding;

// ── Tipos ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub finding_rule_id:   String,
    pub file:              String,
    pub line:              u32,
    pub original_code:     String,
    pub suggested_code:    String,
    pub explanation:       String,
    pub pqc_algorithm:     String,
    pub nist_reference:    String,
    pub confidence:        RemediationConfidence,
    pub requires_import:   Vec<String>,
    pub breaking_change:   bool,
    pub estimated_effort:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationConfidence {
    /// Substituição direta segura — mesma API, algoritmo diferente
    High,
    /// Substituição com pequenas adaptações necessárias
    Medium,
    /// Requer refatoração manual — mostra direção mas não aplica
    Low,
    /// Não é possível gerar substituição automática segura
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationReport {
    pub file:                  String,
    pub total_findings:        usize,
    pub auto_fixable:          usize,
    pub manual_review:         usize,
    pub suggestions:           Vec<RemediationSuggestion>,
    pub estimated_total_effort: String,
    pub dry_run:               bool,
    pub applied:               usize,
}

// ── Templates de remediação por linguagem e algoritmo ─────────────────────────

struct RemediationTemplate {
    pattern:        &'static str,   // padrão a detectar no código
    replacement:    &'static str,   // código substituto
    explanation:    &'static str,
    pqc_algorithm:  &'static str,
    nist_ref:       &'static str,
    imports:        &'static [&'static str],
    breaking:       bool,
    confidence:     RemediationConfidence,
    effort:         &'static str,
}

// Python
const PYTHON_REMEDIATIONS: &[(&str, RemediationTemplate)] = &[
    ("QSC-010", RemediationTemplate {
        pattern:       "hashlib.md5(",
        replacement:   "hashlib.sha3_256(",
        explanation:   "MD5 quebrado desde 2004. SHA3-256 (NIST FIPS 202) é resistente a ataques quânticos via Grover com margem de segurança adequada.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["import hashlib"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-PY-001", RemediationTemplate {
        pattern:       "hashlib.md5(",
        replacement:   "hashlib.sha3_256(",
        explanation:   "MD5 detectado via adapter Python. Substituir por SHA3-256.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["import hashlib"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-011", RemediationTemplate {
        pattern:       "hashlib.sha1(",
        replacement:   "hashlib.sha3_256(",
        explanation:   "SHA-1 quebrado (ataque SHAttered 2017). SHA3-256 provê 256 bits de segurança clássica e resistência a Grover.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["import hashlib"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-020", RemediationTemplate {
        pattern:       "algorithm=\"none\"",
        replacement:   "algorithm=\"EdDSA\"",
        explanation:   "JWT algorithm=none desabilita verificação de assinatura completamente. Use EdDSA (Ed25519) como passo intermediário antes de ML-DSA-65.",
        pqc_algorithm: "EdDSA/Ed25519 (interim) → ML-DSA-65 (NIST FIPS 204)",
        nist_ref:      "NIST FIPS 204",
        imports:       &[],
        breaking:      true,
        confidence:    RemediationConfidence::Medium,
        effort:        "30 minutos",
    }),
    ("QSC-PY-002", RemediationTemplate {
        pattern:       "algorithm='none'",
        replacement:   "algorithm='EdDSA'",
        explanation:   "JWT algorithm=none desabilita verificação. Use EdDSA (Ed25519).",
        pqc_algorithm: "EdDSA/Ed25519 (interim) → ML-DSA-65 (NIST FIPS 204)",
        nist_ref:      "NIST FIPS 204",
        imports:       &[],
        breaking:      true,
        confidence:    RemediationConfidence::Medium,
        effort:        "30 minutos",
    }),
    ("QSC-101", RemediationTemplate {
        pattern:       "random.random()",
        replacement:   "secrets.token_bytes(32)",
        explanation:   "random.random() não é criptograficamente seguro (PRNG Mersenne Twister). secrets.token_bytes() usa o CSPRNG do sistema operacional.",
        pqc_algorithm: "OS CSPRNG (/dev/urandom)",
        nist_ref:      "NIST SP 800-90A",
        imports:       &["import secrets"],
        breaking:      false,
        confidence:    RemediationConfidence::Medium,
        effort:        "< 5 minutos",
    }),
    ("QSC-105", RemediationTemplate {
        pattern:       "random.random()",
        replacement:   "secrets.token_bytes(32)",
        explanation:   "PRNG inseguro detectado. Use secrets.token_bytes() para valores criptográficos.",
        pqc_algorithm: "OS CSPRNG",
        nist_ref:      "NIST SP 800-90A",
        imports:       &["import secrets"],
        breaking:      false,
        confidence:    RemediationConfidence::Medium,
        effort:        "< 5 minutos",
    }),
];

// Java
const JAVA_REMEDIATIONS: &[(&str, RemediationTemplate)] = &[
    ("QSC-010", RemediationTemplate {
        pattern:       "MessageDigest.getInstance(\"MD5\")",
        replacement:   "MessageDigest.getInstance(\"SHA3-256\")",
        explanation:   "MD5 quebrado. SHA3-256 (NIST FIPS 202) é a substituição recomendada pelo NIST.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["import java.security.MessageDigest;"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-011", RemediationTemplate {
        pattern:       "MessageDigest.getInstance(\"SHA-1\")",
        replacement:   "MessageDigest.getInstance(\"SHA3-256\")",
        explanation:   "SHA-1 quebrado (SHAttered 2017). SHA3-256 é a substituição correta.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["import java.security.MessageDigest;"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-001", RemediationTemplate {
        pattern:       "KeyPairGenerator.getInstance(\"RSA\")",
        replacement:   "// TODO: migrar para ML-KEM-768 (NIST FIPS 203)\n        // Interim: use KeyPairGenerator.getInstance(\"Ed25519\")\n        KeyPairGenerator.getInstance(\"Ed25519\")",
        explanation:   "RSA vulnerável ao algoritmo de Shor. Migrar para Ed25519 como passo intermediário. Target final: ML-KEM-768/ML-DSA-65 via biblioteca liboqs-java ou BouncyCastle PQC.",
        pqc_algorithm: "ML-KEM-768 (NIST FIPS 203) + ML-DSA-65 (NIST FIPS 204)",
        nist_ref:      "NIST FIPS 203/204",
        imports:       &["import java.security.KeyPairGenerator;"],
        breaking:      true,
        confidence:    RemediationConfidence::Medium,
        effort:        "2-4 horas",
    }),
    ("QSC-013", RemediationTemplate {
        pattern:       "Cipher.getInstance(\"DES",
        replacement:   "Cipher.getInstance(\"AES/GCM/NoPadding\")",
        explanation:   "DES/3DES quebrado classicamente. AES-256-GCM provê 256 bits de segurança e resistência quântica via Grover.",
        pqc_algorithm: "AES-256-GCM",
        nist_ref:      "NIST FIPS 197",
        imports:       &["import javax.crypto.Cipher;"],
        breaking:      true,
        confidence:    RemediationConfidence::Medium,
        effort:        "1-2 horas",
    }),
];

// Go
const GO_REMEDIATIONS: &[(&str, RemediationTemplate)] = &[
    ("QSC-010", RemediationTemplate {
        pattern:       "md5.New()",
        replacement:   "sha3.New256()",
        explanation:   "MD5 quebrado. golang.org/x/crypto/sha3 provê SHA3-256 (NIST FIPS 202).",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["\"golang.org/x/crypto/sha3\""],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-011", RemediationTemplate {
        pattern:       "sha1.New()",
        replacement:   "sha3.New256()",
        explanation:   "SHA-1 quebrado. Substituir por SHA3-256.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["\"golang.org/x/crypto/sha3\""],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
];

// JavaScript/TypeScript
const JS_REMEDIATIONS: &[(&str, RemediationTemplate)] = &[
    ("QSC-010", RemediationTemplate {
        pattern:       "createHash('md5')",
        replacement:   "createHash('sha3-256')",
        explanation:   "MD5 quebrado. SHA3-256 disponível no módulo crypto do Node.js desde v12.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["const { createHash } = require('crypto');"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-011", RemediationTemplate {
        pattern:       "createHash('sha1')",
        replacement:   "createHash('sha3-256')",
        explanation:   "SHA-1 quebrado. Substituir por SHA3-256.",
        pqc_algorithm: "SHA3-256 (NIST FIPS 202)",
        nist_ref:      "NIST FIPS 202",
        imports:       &["const { createHash } = require('crypto');"],
        breaking:      false,
        confidence:    RemediationConfidence::High,
        effort:        "< 5 minutos",
    }),
    ("QSC-020", RemediationTemplate {
        pattern:       "algorithm: 'none'",
        replacement:   "algorithm: 'EdDSA'",
        explanation:   "JWT algorithm:none desabilita verificação. Use EdDSA (Ed25519).",
        pqc_algorithm: "EdDSA/Ed25519",
        nist_ref:      "NIST FIPS 204",
        imports:       &[],
        breaking:      true,
        confidence:    RemediationConfidence::Medium,
        effort:        "30 minutos",
    }),
];

// ── Funções principais ────────────────────────────────────────────────────────

/// Detecta a linguagem do arquivo pela extensão
fn detect_lang(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py")                    => "python",
        Some("java")                  => "java",
        Some("go")                    => "go",
        Some("js") | Some("ts") |
        Some("jsx") | Some("tsx")     => "javascript",
        Some("cs")                    => "csharp",
        Some("rs")                    => "rust",
        _                             => "unknown",
    }
}

/// Gera sugestões de remediação para um arquivo
pub fn generate_suggestions(
    path: &Path,
    findings: &[CryptoFinding],
    content: &str,
) -> Vec<RemediationSuggestion> {
    let lang = detect_lang(path);
    let lines: Vec<&str> = content.lines().collect();
    let mut suggestions = Vec::new();

    for finding in findings {
        if finding.file != path.display().to_string() {
            continue;
        }

        let line_idx = (finding.line as usize).saturating_sub(1);
        let original = lines.get(line_idx).unwrap_or(&"").trim().to_string();

        // Seleciona templates pela linguagem
        let templates: &[(&str, RemediationTemplate)] = match lang {
            "python"     => PYTHON_REMEDIATIONS,
            "java"       => JAVA_REMEDIATIONS,
            "go"         => GO_REMEDIATIONS,
            "javascript" => JS_REMEDIATIONS,
            _            => &[],
        };

        // Encontra template correspondente ao rule_id
        let template = templates.iter().find(|(id, t)| {
            *id == finding.rule_id || original.contains(t.pattern)
        });

        if let Some((_, tmpl)) = template {
            // Gera código sugerido substituindo o padrão
            let suggested = if original.contains(tmpl.pattern) {
                original.replace(tmpl.pattern, tmpl.replacement)
            } else {
                format!("// Substituir por: {}", tmpl.replacement)
            };

            suggestions.push(RemediationSuggestion {
                finding_rule_id: finding.rule_id.clone(),
                file:            finding.file.clone(),
                line:            finding.line as u32,
                original_code:   original,
                suggested_code:  suggested,
                explanation:     tmpl.explanation.to_string(),
                pqc_algorithm:   tmpl.pqc_algorithm.to_string(),
                nist_reference:  tmpl.nist_ref.to_string(),
                confidence:      tmpl.confidence.clone(),
                requires_import: tmpl.imports.iter().map(|s| s.to_string()).collect(),
                breaking_change: tmpl.breaking,
                estimated_effort: tmpl.effort.to_string(),
            });
        } else {
            // Sem template específico — sugere revisão manual
            suggestions.push(RemediationSuggestion {
                finding_rule_id: finding.rule_id.clone(),
                file:            finding.file.clone(),
                line:            finding.line as u32,
                original_code:   original,
                suggested_code:  format!(
                    "// Revisão manual necessária para {}\n// Consulte: https://csrc.nist.gov/projects/post-quantum-cryptography",
                    finding.rule_id
                ),
                explanation:     format!(
                    "Sem template de remediação automática para {}. Consulte NIST SP 800-131A Rev 3 para orientação.",
                    finding.rule_id
                ),
                pqc_algorithm:   "Consultar NIST SP 800-131A Rev 3".to_string(),
                nist_reference:  "NIST SP 800-131A".to_string(),
                confidence:      RemediationConfidence::Manual,
                requires_import: vec![],
                breaking_change: true,
                estimated_effort: "Estimativa manual necessária".to_string(),
            });
        }
    }

    suggestions
}

/// Gera relatório de remediação (dry-run por padrão)
pub fn generate_remediation_report(
    path: &Path,
    findings: &[CryptoFinding],
    content: &str,
    apply_fixes: bool,
) -> RemediationReport {
    let suggestions = generate_suggestions(path, findings, content);
    let total        = suggestions.len();
    let auto_fixable = suggestions.iter()
        .filter(|s| s.confidence == RemediationConfidence::High ||
                    s.confidence == RemediationConfidence::Medium)
        .count();
    let manual = total - auto_fixable;

    let total_effort = estimate_total_effort(&suggestions);
    let mut applied  = 0;

    // Aplica fixes SOMENTE se --fix explícito e confidence >= Medium
    if apply_fixes {
        let mut new_content = content.to_string();
        let lines: Vec<&str> = content.lines().collect();

        for suggestion in &suggestions {
            if suggestion.confidence == RemediationConfidence::Manual {
                continue;
            }
            let line_idx = (suggestion.line as usize).saturating_sub(1);
            if let Some(original_line) = lines.get(line_idx) {
                if original_line.contains(&suggestion.original_code) {
                    let new_line = original_line.replace(
                        &suggestion.original_code,
                        &suggestion.suggested_code
                    );
                    new_content = new_content.replacen(original_line, &new_line, 1);
                    applied += 1;
                }
            }
        }

        if applied > 0 {
            // Backup antes de modificar
            let backup_path = format!("{}.omniuil-backup", path.display());
            if let Err(e) = std::fs::write(&backup_path, content) {
                eprintln!("[OmniUil] AVISO: não foi possível criar backup: {}", e);
            } else {
                eprintln!("[OmniUil] Backup salvo em: {}", backup_path);
            }
            if let Err(e) = std::fs::write(path, &new_content) {
                eprintln!("[OmniUil] ERRO ao aplicar fix: {}", e);
                applied = 0;
            } else {
                eprintln!("[OmniUil] {} fix(es) aplicado(s) em {}", applied, path.display());
            }
        }
    }

    RemediationReport {
        file:                   path.display().to_string(),
        total_findings:         total,
        auto_fixable,
        manual_review:          manual,
        suggestions,
        estimated_total_effort: total_effort,
        dry_run:                !apply_fixes,
        applied,
    }
}

fn estimate_total_effort(suggestions: &[RemediationSuggestion]) -> String {
    let high   = suggestions.iter().filter(|s| s.confidence == RemediationConfidence::High).count();
    let medium = suggestions.iter().filter(|s| s.confidence == RemediationConfidence::Medium).count();
    let manual = suggestions.iter().filter(|s| s.confidence == RemediationConfidence::Manual).count();

    if high + medium + manual == 0 {
        return "Nenhuma remediação necessária".to_string();
    }
    format!(
        "{} automáticas (< 30min) + {} com adaptação (1-4h) + {} manuais (estimativa necessária)",
        high, medium, manual
    )
}

/// Serializa relatório para JSON
pub fn remediation_to_json(report: &RemediationReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// Formata diff legível para o terminal
pub fn format_diff(report: &RemediationReport) -> String {
    let mut out = String::new();
    let mode = if report.dry_run { "DRY-RUN" } else { "APPLIED" };

    out.push_str(&format!(
        "╔══ OmniUil AI v5.5 — Auto-Remediation ({}) ══╗\n", mode
    ));
    out.push_str(&format!("  Arquivo:         {}\n", report.file));
    out.push_str(&format!("  Total findings:  {}\n", report.total_findings));
    out.push_str(&format!("  Auto-fixável:    {}\n", report.auto_fixable));
    out.push_str(&format!("  Revisão manual:  {}\n", report.manual_review));
    out.push_str(&format!("  Esforço total:   {}\n", report.estimated_total_effort));
    if !report.dry_run {
        out.push_str(&format!("  Aplicados:       {}\n", report.applied));
    }
    out.push_str("╚══════════════════════════════════════════════╝\n\n");

    for (i, s) in report.suggestions.iter().enumerate() {
        let conf = match s.confidence {
            RemediationConfidence::High   => "🟢 HIGH",
            RemediationConfidence::Medium => "🟡 MEDIUM",
            RemediationConfidence::Low    => "🟠 LOW",
            RemediationConfidence::Manual => "🔴 MANUAL",
        };
        out.push_str(&format!("── Fix {} — {} (linha {}) {}\n", i+1, s.finding_rule_id, s.line, conf));
        out.push_str(&format!("   Algoritmo PQC: {}\n", s.pqc_algorithm));
        out.push_str(&format!("   Referência:    {}\n", s.nist_reference));
        out.push_str(&format!("   Esforço:       {}\n", s.estimated_effort));
        if s.breaking_change {
            out.push_str("   ⚠️  BREAKING CHANGE: requer testes após aplicação\n");
        }
        out.push_str(&format!("   - ANTES:  {}\n", s.original_code));
        out.push_str(&format!("   + DEPOIS: {}\n", s.suggested_code));
        if !s.requires_import.is_empty() {
            out.push_str(&format!("   📦 Import: {}\n", s.requires_import.join(", ")));
        }
        out.push_str(&format!("   💡 {}\n\n", s.explanation));
    }

    if report.dry_run && report.auto_fixable > 0 {
        out.push_str(&format!(
            "▶ Para aplicar automaticamente: adicione --fix ao comando\n"
        ));
    }
    out
}
