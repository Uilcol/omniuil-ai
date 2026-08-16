//! # Enterprise Configuration — .qsec.toml
//!
//! Sistema de configuração por projeto. O arquivo `.qsec.toml` na raiz do
//! repositório controla:
//!   - Regras habilitadas/desabilitadas
//!   - Paths ignorados (vendor, generated, tests)
//!   - Thresholds de severidade para CI/CD
//!   - Integrações enterprise (Slack, Teams, PagerDuty, JIRA)
//!   - Política de rotação de chaves
//!   - Configurações de SBOM
//!
//! # Exemplo .qsec.toml
//!
//! ```toml
//! [scanner]
//! fail_on = ["CRITICAL", "HIGH"]
//! ignore_paths = ["vendor/", "generated/", "*.test.rs"]
//! disabled_rules = ["QSC-021"]   # aceita HMAC interno
//! extra_patterns = [
//!   { id = "CUSTOM-001", severity = "HIGH", pattern = "insecure_api_v1" }
//! ]
//!
//! [keys]
//! rotation_days     = 30
//! alert_before_days = 7
//! require_hsm       = false
//!
//! [jwt]
//! default_ttl_secs = 3600
//! max_ttl_secs     = 86400
//! clock_skew_secs  = 30
//!
//! [sbom]
//! include_dev_deps = false
//! output_format    = "cyclonedx-json"
//!
//! [integrations.slack]
//! webhook_url = "${SLACK_WEBHOOK_URL}"   # env var expansion
//! channel     = "#security-alerts"
//! min_severity = "HIGH"
//!
//! [integrations.jira]
//! url        = "https://company.atlassian.net"
//! project    = "SEC"
//! token      = "${JIRA_API_TOKEN}"
//! auto_create = true
//!
//! [integrations.pagerduty]
//! routing_key  = "${PD_ROUTING_KEY}"
//! min_severity = "CRITICAL"
//! ```

use std::path::Path;

use serde::{Deserialize, Serialize};

// ─── Estrutura Principal ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsecConfig {
    #[serde(default)]
    pub scanner:      ScannerConfig,
    #[serde(default)]
    pub keys:         KeysConfig,
    #[serde(default)]
    pub jwt:          JwtConfig,
    #[serde(default)]
    pub sbom:         SbomConfig,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
    #[serde(default)]
    pub pipeline:     PipelineConfig,
}

impl Default for QsecConfig {
    fn default() -> Self {
        Self {
            scanner:      ScannerConfig::default(),
            keys:         KeysConfig::default(),
            jwt:          JwtConfig::default(),
            sbom:         SbomConfig::default(),
            integrations: IntegrationsConfig::default(),
            pipeline:     PipelineConfig::default(),
        }
    }
}

// ─── Scanner Config ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Severidades que causam exit code 1 no CI
    #[serde(default = "default_fail_on")]
    pub fail_on: Vec<String>,

    /// Paths ignorados (glob patterns)
    #[serde(default = "default_ignore_paths")]
    pub ignore_paths: Vec<String>,

    /// Regras desabilitadas para este projeto
    #[serde(default)]
    pub disabled_rules: Vec<String>,

    /// Padrões customizados adicionais
    #[serde(default)]
    pub extra_patterns: Vec<CustomPattern>,

    /// Extensões de arquivo a escanear (além das defaults)
    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,

    /// Máximo de findings antes de truncar o report
    #[serde(default = "default_max_findings")]
    pub max_findings: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            fail_on:         default_fail_on(),
            ignore_paths:    default_ignore_paths(),
            disabled_rules:  Vec::new(),
            extra_patterns:  Vec::new(),
            extensions:      default_extensions(),
            max_findings:    500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub id:          String,
    pub severity:    String,
    pub title:       String,
    pub pattern:     String,
    pub description: String,
    pub recommendation: String,
}

fn default_fail_on()      -> Vec<String> { vec!["CRITICAL".into(), "HIGH".into()] }
fn default_ignore_paths() -> Vec<String> {
    vec!["vendor/".into(), "target/".into(), "node_modules/".into(),
         ".git/".into(), "generated/".into(), "*.min.js".into(),
         "test/".into(), "tests/".into(), "*Test.java".into(),
         "*_test.go".into(), "*.test.ts".into(), "*.test.js".into(),
         "spec/".into(), "__tests__/".into(), "example/".into(),
         "examples/".into()]
}
fn default_extensions()   -> Vec<String> {
    vec!["rs".into(), "py".into(), "go".into(), "java".into(),
         "js".into(), "ts".into(), "cpp".into(), "c".into(),
         "h".into(), "kt".into(), "swift".into(), "rb".into()]
}
fn default_max_findings() -> usize { 500 }

// ─── Keys Config ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysConfig {
    /// TTL das chaves em dias
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,

    /// Dias antes de vencer para alertar
    #[serde(default = "default_alert_before")]
    pub alert_before_days: u32,

    /// Exige HSM para operações em produção
    #[serde(default)]
    pub require_hsm: bool,

    /// Rotação automática quando TTL expira
    #[serde(default = "bool_true")]
    pub auto_rotate: bool,
}

impl Default for KeysConfig {
    fn default() -> Self {
        Self {
            rotation_days:    default_rotation_days(),
            alert_before_days: default_alert_before(),
            require_hsm:      false,
            auto_rotate:      true,
        }
    }
}

fn default_rotation_days() -> u32 { 30 }
fn default_alert_before()  -> u32 { 7 }
fn bool_true()             -> bool { true }

// ─── JWT Config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    #[serde(default = "default_jwt_ttl")]
    pub default_ttl_secs: u64,

    #[serde(default = "default_jwt_max_ttl")]
    pub max_ttl_secs: u64,

    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,

    /// Audience padrão se não especificado
    #[serde(default = "default_audience")]
    pub default_audience: String,

    /// Issuer padrão
    #[serde(default = "default_issuer")]
    pub default_issuer: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs:  default_jwt_ttl(),
            max_ttl_secs:      default_jwt_max_ttl(),
            clock_skew_secs:   default_clock_skew(),
            default_audience:  default_audience(),
            default_issuer:    default_issuer(),
        }
    }
}

fn default_jwt_ttl()    -> u64 { 3600 }
fn default_jwt_max_ttl() -> u64 { 86400 }
fn default_clock_skew() -> u64 { 30 }
fn default_audience()   -> String { "qsec-protected".to_string() }
fn default_issuer()     -> String { "qsec".to_string() }

// ─── SBOM Config ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomConfig {
    #[serde(default)]
    pub include_dev_deps: bool,

    #[serde(default = "default_sbom_format")]
    pub output_format: String,

    /// Licenças proibidas — gera alerta se encontradas
    #[serde(default)]
    pub denied_licenses: Vec<String>,

    /// Componentes com vulnerabilidades conhecidas bloqueados
    #[serde(default = "bool_true")]
    pub block_known_vulnerable: bool,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            include_dev_deps:      false,
            output_format:         default_sbom_format(),
            denied_licenses:       vec!["GPL-3.0".into(), "AGPL-3.0".into()],
            block_known_vulnerable: true,
        }
    }
}

fn default_sbom_format() -> String { "cyclonedx-json".to_string() }

// ─── Integrations ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    pub slack:      Option<SlackConfig>,
    pub teams:      Option<TeamsConfig>,
    pub pagerduty:  Option<PagerDutyConfig>,
    pub jira:       Option<JiraConfig>,
    pub github:     Option<GitHubConfig>,
    pub webhook:    Option<WebhookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url:  String,
    #[serde(default = "default_slack_channel")]
    pub channel:      String,
    #[serde(default = "default_min_sev_high")]
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub webhook_url:  String,
    #[serde(default = "default_min_sev_high")]
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub routing_key:  String,
    #[serde(default = "default_min_sev_critical")]
    pub min_severity: String,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    pub url:          String,
    pub project:      String,
    pub token:        String,
    pub email:        Option<String>,
    #[serde(default = "bool_true")]
    pub auto_create:  bool,
    #[serde(default = "default_jira_issue_type")]
    pub issue_type:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// Token para PR annotations (GITHUB_TOKEN)
    pub token:          Option<String>,
    /// Repositório: owner/repo
    pub repository:     Option<String>,
    #[serde(default = "bool_true")]
    pub pr_annotations: bool,
    #[serde(default = "bool_true")]
    pub upload_sarif:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url:          String,
    #[serde(default = "default_webhook_method")]
    pub method:       String,
    pub headers:      Option<std::collections::HashMap<String, String>>,
    #[serde(default = "default_min_sev_high")]
    pub min_severity: String,
}

fn default_slack_channel()    -> String { "#security-alerts".to_string() }
fn default_min_sev_high()     -> String { "HIGH".to_string() }
fn default_min_sev_critical() -> String { "CRITICAL".to_string() }
fn default_jira_issue_type()  -> String { "Bug".to_string() }
fn default_webhook_method()   -> String { "POST".to_string() }

// ─── Pipeline Config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Habilita SBOM no pipeline
    #[serde(default = "bool_true")]
    pub generate_sbom: bool,

    /// Habilita assinatura de artefatos
    #[serde(default = "bool_true")]
    pub sign_artifacts: bool,

    /// Habilita attestation SLSA
    #[serde(default = "bool_true")]
    pub attest: bool,

    /// Diretório de output
    #[serde(default = "default_out_dir")]
    pub output_dir: String,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            generate_sbom: true,
            sign_artifacts: true,
            attest:         true,
            output_dir:     default_out_dir(),
        }
    }
}

fn default_out_dir() -> String { "./qsec-out".to_string() }

// ─── Loader ───────────────────────────────────────────────────────────────────

impl QsecConfig {
    /// Carrega configuração de .qsec.toml no diretório atual ou pai.
    pub fn load_from_dir(dir: &Path) -> Self {
        // Procura .qsec.toml em dir e pais (até 5 níveis)
        let mut current = dir.to_path_buf();
        for _ in 0..5 {
            let config_path = current.join(".qsec.toml");
            if config_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    match toml::from_str::<QsecConfig>(&content) {
                        Ok(mut cfg) => {
                            cfg.expand_env_vars();
                            return cfg;
                        }
                        Err(e) => {
                            eprintln!("[QSEC] Warning: .qsec.toml parse error: {e}");
                        }
                    }
                }
            }
            if !current.pop() { break; }
        }
        Self::default()
    }

    /// Expande variáveis de ambiente no formato ${VAR_NAME}.
    fn expand_env_vars(&mut self) {
        let expand = |s: &str| -> String {
            let mut result = s.to_string();
            while let (Some(start), Some(end)) = (result.find("${"), result.find('}')) {
                if start < end {
                    let var_name = result[start+2..end].to_string();
                    let value = std::env::var(&var_name).unwrap_or_default();
                    result = format!("{}{}{}", &result[..start], value, &result[end+1..]);
                } else {
                    break;
                }
            }
            result
        };

        if let Some(slack) = &mut self.integrations.slack {
            slack.webhook_url = expand(&slack.webhook_url);
        }
        if let Some(pd) = &mut self.integrations.pagerduty {
            pd.routing_key = expand(&pd.routing_key);
        }
        if let Some(jira) = &mut self.integrations.jira {
            jira.token = expand(&jira.token);
            jira.url   = expand(&jira.url);
        }
        if let Some(gh) = &mut self.integrations.github {
            if let Some(token) = &gh.token {
                gh.token = Some(expand(token));
            }
        }
    }

    /// Verifica se um path deve ser ignorado segundo ignore_paths.
    pub fn should_ignore(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.scanner.ignore_paths.iter().any(|pattern| {
            let pattern_lower = pattern.to_lowercase();
            if pattern.ends_with('/') {
                // Diretório: "test/" casa qualquer path contendo "/test/" ou iniciando com "test/"
                path_lower.contains(&pattern_lower)
            } else if pattern.starts_with("*.") {
                // Extensão: "*.min.js" casa qualquer path terminado em ".min.js"
                let ext = &pattern_lower[1..];
                path_lower.ends_with(ext)
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                // Sufixo genérico: "*Test.java" casa "FooTest.java", "*_test.go" casa "bar_test.go"
                path_lower.ends_with(&suffix.to_lowercase())
            } else {
                // Substring simples (fallback)
                path_lower.contains(&pattern_lower)
            }
        })
    }

    /// Verifica se uma regra está habilitada.
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        !self.scanner.disabled_rules.iter().any(|r| r == rule_id)
    }

    /// Verifica se a severidade causa falha no CI.
    pub fn should_fail(&self, severity: &str) -> bool {
        self.scanner.fail_on.iter().any(|s| s == severity)
    }

    /// Gera um .qsec.toml de exemplo com todas as opções.
    pub fn example_toml() -> &'static str {
        r##"# .qsec.toml — QSEC Enterprise Configuration
# Coloque este arquivo na raiz do repositório.
# Variáveis de ambiente são expandidas com ${VAR_NAME}.

[scanner]
# Severidades que causam exit code 1 (falha no CI)
fail_on = ["CRITICAL", "HIGH"]

# Paths ignorados (glob patterns)
ignore_paths = [
  "vendor/",
  "target/",
  "node_modules/",
  "generated/",
  "*.test.rs",
  "*.spec.ts",
]

# Regras desabilitadas para este projeto
# disabled_rules = ["QSC-021"]  # aceita HMAC em contextos internos

# Padrões customizados adicionais
[[scanner.extra_patterns]]
id          = "CUSTOM-001"
severity    = "HIGH"
title       = "API insegura v1 detectada"
pattern     = "insecure_api_v1|legacy_crypto"
description = "API legada com crypto fraca detectada."
recommendation = "Migre para a API v3 com suporte PQC."

[keys]
rotation_days     = 30   # TTL das chaves em dias
alert_before_days = 7    # Alertar X dias antes do vencimento
auto_rotate       = true # Rotação automática

[jwt]
default_ttl_secs = 3600    # 1 hora
max_ttl_secs     = 86400   # 24 horas (máximo permitido)
clock_skew_secs  = 30      # tolerância de clock
default_audience = "api.example.com"
default_issuer   = "qsec"

[sbom]
include_dev_deps        = false
output_format           = "cyclonedx-json"
block_known_vulnerable  = true
denied_licenses         = ["GPL-3.0", "AGPL-3.0"]

[pipeline]
generate_sbom  = true
sign_artifacts = true
attest         = true
output_dir     = "./qsec-out"

# ─── Integrações Enterprise ───────────────────────────────────────────────────

[integrations.slack]
webhook_url  = "${SLACK_WEBHOOK_URL}"
channel      = "#security-alerts"
min_severity = "HIGH"

[integrations.teams]
webhook_url  = "${TEAMS_WEBHOOK_URL}"
min_severity = "CRITICAL"

[integrations.pagerduty]
routing_key  = "${PD_ROUTING_KEY}"
min_severity = "CRITICAL"
service_name = "QSEC Security"

[integrations.jira]
url         = "https://company.atlassian.net"
project     = "SEC"
token       = "${JIRA_API_TOKEN}"
email       = "${JIRA_EMAIL}"
auto_create = true
issue_type  = "Bug"

[integrations.github]
token          = "${GITHUB_TOKEN}"
pr_annotations = true
upload_sarif   = true

[integrations.webhook]
url          = "${SECURITY_WEBHOOK_URL}"
method       = "POST"
min_severity = "HIGH"
[integrations.webhook.headers]
Authorization = "Bearer ${WEBHOOK_TOKEN}"
Content-Type  = "application/json"
"##
    }
}
