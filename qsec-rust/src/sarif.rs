//! # SARIF 2.1.0 Output — GitHub Security Tab Integration
//!
//! Gera output no formato SARIF (Static Analysis Results Interchange Format)
//! para integração nativa com:
//!   - GitHub Advanced Security (Security tab, PR annotations)
//!   - Azure DevOps Security Center
//!   - VS Code SARIF Viewer extension
//!   - SonarQube, Checkmarx, Veracode
//!
//! Referência: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use serde::{Deserialize, Serialize};
use crate::scanner::{CryptoFinding, Severity};
use crate::VERSION;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json";

// ─── SARIF Root ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema:  String,
    pub version: String,
    pub runs:    Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool:    SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(rename = "columnKind")]
    pub column_kind: String,
}

// ─── Tool ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifToolDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifToolDriver {
    pub name:             String,
    pub version:          String,
    #[serde(rename = "informationUri")]
    pub information_uri:  String,
    pub rules:            Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id:               String,
    pub name:             String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description:  SarifMessage,
    #[serde(rename = "helpUri")]
    pub help_uri:          String,
    pub help:              SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfig,
    pub properties:        SarifRuleProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleConfig {
    pub level: String,   // "error" | "warning" | "note"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags:      Vec<String>,
    pub precision: String,  // "high" | "medium" | "low"
    #[serde(rename = "problem.severity")]
    pub problem_severity: String,
    #[serde(rename = "security-severity")]
    pub security_severity: String, // CVSS-like 0.0-10.0 string
}

// ─── Result ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id:   String,
    pub level:     String,
    pub message:   SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: SarifFingerprints,
    pub properties: SarifResultProperties,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifFingerprints {
    #[serde(rename = "primaryLocationLineHash/v1")]
    pub line_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResultProperties {
    pub severity:          String,
    pub recommendation:    String,
    #[serde(rename = "qsecRuleId")]
    pub qsec_rule_id:      String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    pub message: Option<SarifMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region:            SarifRegion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri:       String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line:   usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    pub snippet:      Option<SarifArtifactContent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactContent {
    pub text: String,
}

// ─── Conversão ────────────────────────────────────────────────────────────────

/// Converte findings QSEC para SARIF 2.1.0.
pub fn findings_to_sarif(findings: &[CryptoFinding]) -> SarifLog {
    // Coleta regras únicas
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules: Vec<SarifRule> = Vec::new();

    for f in findings {
        if seen_rules.insert(f.rule_id.clone()) {
            rules.push(finding_to_rule(f));
        }
    }

    // Ordena regras por ID
    rules.sort_by(|a, b| a.id.cmp(&b.id));

    let results: Vec<SarifResult> = findings
        .iter()
        .map(finding_to_result)
        .collect();

    SarifLog {
        schema:  SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolDriver {
                    name:            "QSEC".to_string(),
                    version:         VERSION.to_string(),
                    information_uri: "https://github.com/yourorg/qsec".to_string(),
                    rules,
                },
            },
            results,
            column_kind: "utf16CodeUnits".to_string(),
        }],
    }
}

fn severity_to_level(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "error",
        Severity::High     => "error",
        Severity::Medium   => "warning",
        Severity::Low      => "note",
    }
}

fn severity_to_security_score(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High     => "7.5",
        Severity::Medium   => "5.0",
        Severity::Low      => "2.5",
    }
}

fn finding_to_rule(f: &CryptoFinding) -> SarifRule {
    let help_text = format!(
        "**{}**\n\n{}\n\n**Recomendação:** {}\n\n**Referências:**\n- NIST FIPS 203 (ML-KEM)\n- NIST FIPS 204 (ML-DSA)\n- NSA CNSA 2.0",
        f.title, f.description, f.recommendation
    );

    SarifRule {
        id:   f.rule_id.clone(),
        name: f.title.replace(' ', ""),
        short_description: SarifMessage { text: f.title.clone() },
        full_description:  SarifMessage { text: f.description.clone() },
        help_uri: format!("https://docs.qsec.io/rules/{}", f.rule_id.to_lowercase()),
        help: SarifMessage { text: help_text },
        default_configuration: SarifRuleConfig {
            level: severity_to_level(&f.severity).to_string(),
        },
        properties: SarifRuleProperties {
            tags: vec![
                "security".to_string(),
                "cryptography".to_string(),
                "post-quantum".to_string(),
                f.severity.to_string().to_lowercase(),
            ],
            precision: "high".to_string(),
            problem_severity: f.severity.to_string(),
            security_severity: severity_to_security_score(&f.severity).to_string(),
        },
    }
}

fn finding_to_result(f: &CryptoFinding) -> SarifResult {
    // Normaliza path para URI relativo (GitHub espera caminhos relativos)
    let uri = f.file
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();

    // Fingerprint simples baseado em file+line+rule
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    f.file.hash(&mut hasher);
    f.line.hash(&mut hasher);
    f.rule_id.hash(&mut hasher);
    let fingerprint = format!("{:016x}", hasher.finish());

    SarifResult {
        rule_id: f.rule_id.clone(),
        level:   severity_to_level(&f.severity).to_string(),
        message: SarifMessage {
            text: format!("{}: {}", f.title, f.description),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri,
                    uri_base_id: "%SRCROOT%".to_string(),
                },
                region: SarifRegion {
                    start_line:   f.line.max(1),
                    start_column: f.column.max(1),
                    snippet: if f.code_snippet.is_empty() {
                        None
                    } else {
                        Some(SarifArtifactContent { text: f.code_snippet.clone() })
                    },
                },
            },
            message: Some(SarifMessage { text: f.recommendation.clone() }),
        }],
        partial_fingerprints: SarifFingerprints { line_hash: fingerprint },
        properties: SarifResultProperties {
            severity:       f.severity.to_string(),
            recommendation: f.recommendation.clone(),
            qsec_rule_id:   f.rule_id.clone(),
        },
    }
}

/// Serializa SARIF log para JSON formatado.
pub fn to_json(log: &SarifLog) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(log)
}
