//! # Motor de Regras YAML — Absorção do OmniUil AI
//!
//! Carrega regras customizadas de arquivos `.yaml` em `.qsec/rules/`.
//! Permite adicionar, desabilitar ou modificar regras sem recompilar o QSEC.
//!
//! ## Formato do arquivo
//!
//! ```yaml
//! rules:
//!   - id: "CUSTOM-001"
//!     severity: "HIGH"
//!     title: "API insegura detectada"
//!     description: "Esta API está depreciada e tem vulnerabilidades conhecidas."
//!     recommendation: "Use a API segura alternativa."
//!     pattern: "insecure_api_v1"
//!     languages: []           # vazio = todas as linguagens
//!     taint_sink: false       # true = marca como sink para análise de taint
//!
//!   - id: "CUSTOM-002"
//!     severity: "CRITICAL"
//!     title: "Chave de produção hardcoded"
//!     description: "Chave de produção encontrada no código-fonte."
//!     recommendation: "Use variáveis de ambiente ou Vault."
//!     pattern: "PROD_SECRET_KEY_[A-Za-z0-9]{16,}"
//!     languages: ["python", "javascript", "typescript"]
//! ```
//!
//! ## Segurança
//!
//! - Regras com regex inválido são ignoradas com aviso (nunca crasham o scanner)
//! - Arquivos YAML malformados são ignorados com aviso
//! - Nenhum código externo é executado — apenas matching de regex

use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ─── Tipos públicos ───────────────────────────────────────────────────────────

/// Uma regra definida em YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlRule {
    /// Identificador único (ex: "CUSTOM-001")
    pub id:             String,
    /// Severidade: "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub severity:       String,
    /// Título curto do finding
    pub title:          String,
    /// Descrição detalhada do problema
    pub description:    String,
    /// Recomendação de correção
    pub recommendation: String,
    /// Expressão regular (Rust regex syntax)
    pub pattern:        String,
    /// Filtro de linguagem. Vazio = todas. Ex: ["java", "python"]
    #[serde(default)]
    pub languages:      Vec<String>,
    /// Se true, esta regra é tratada como sink pelo analisador de taint
    #[serde(default)]
    pub taint_sink:     bool,
}

/// Match retornado pelo motor para uma linha de código.
/// Deliberadamente sem dependência de `scanner::CryptoFinding`
/// para evitar importação circular.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id:        String,
    pub severity_str:   String,
    pub title:          String,
    pub description:    String,
    pub recommendation: String,
    /// Coluna (1-indexed) onde o match começou
    pub column:         usize,
    /// Texto exato que fez match
    pub matched_text:   String,
    /// true = este match deve ser rastreado como sink de taint
    pub is_taint_sink:  bool,
}

// ─── Regra compilada (interna) ────────────────────────────────────────────────

struct CompiledRule {
    rule:    YamlRule,
    pattern: Regex,
}

// ─── Container YAML ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct YamlRulesFile {
    #[serde(default)]
    rules: Vec<YamlRule>,
}

// ─── Motor de regras ──────────────────────────────────────────────────────────

/// Carrega e aplica regras YAML customizadas.
///
/// # Exemplo
///
/// ```no_run
/// use std::path::Path;
/// use qsec::rules::RuleEngine;
///
/// let engine = RuleEngine::load_from_dir(Path::new(".qsec/rules"));
/// for err in engine.errors() {
///     eprintln!("Aviso: {err}");
/// }
/// println!("Regras carregadas: {}", engine.rule_count());
/// ```
pub struct RuleEngine {
    compiled: Vec<CompiledRule>,
    errors:   Vec<String>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    /// Cria um motor vazio (sem regras).
    pub fn new() -> Self {
        Self {
            compiled: Vec::new(),
            errors:   Vec::new(),
        }
    }

    /// Carrega todos os arquivos `.yaml` / `.yml` de um diretório.
    /// Retorna silenciosamente se o diretório não existir.
    pub fn load_from_dir(rules_dir: &Path) -> Self {
        let mut engine = Self::new();

        if !rules_dir.is_dir() {
            return engine;
        }

        let entries = match std::fs::read_dir(rules_dir) {
            Ok(e) => e,
            Err(e) => {
                engine.errors.push(format!(
                    "Não foi possível ler o diretório de regras {}: {e}",
                    rules_dir.display()
                ));
                return engine;
            }
        };

        let mut paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();

        // Ordem determinística para reprodutibilidade
        paths.sort();

        for path in paths {
            engine.load_file(&path);
        }

        engine
    }

    /// Carrega regras de um único arquivo YAML.
    pub fn load_file(&mut self, path: &Path) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                self.errors.push(format!(
                    "Falha ao ler {}: {e}",
                    path.display()
                ));
                return;
            }
        };

        // Segurança: detecta arquivos suspeitos (tamanho > 1 MB)
        if content.len() > 1_048_576 {
            self.errors.push(format!(
                "Arquivo de regras muito grande (>1MB), ignorando: {}",
                path.display()
            ));
            return;
        }

        let file: YamlRulesFile = match serde_yaml::from_str(&content) {
            Ok(f) => f,
            Err(e) => {
                self.errors.push(format!(
                    "Erro de parse YAML em {}: {e}",
                    path.display()
                ));
                return;
            }
        };

        let mut loaded = 0usize;
        for rule in file.rules {
            // Validação básica do ID
            if rule.id.is_empty() {
                self.errors.push(format!(
                    "Regra sem ID em {} — ignorada",
                    path.display()
                ));
                continue;
            }

            // Rejeita IDs com caracteres perigosos (path traversal, injeção)
            if rule.id.chars().any(|c| c == '/' || c == '\\' || c == '\0') {
                self.errors.push(format!(
                    "ID de regra inválido '{}' em {} — ignorada",
                    rule.id,
                    path.display()
                ));
                continue;
            }

            // Limita tamanho do padrão para evitar ReDoS
            if rule.pattern.len() > 2048 {
                self.errors.push(format!(
                    "Padrão da regra {} muito longo (>2048 chars) — ignorada",
                    rule.id
                ));
                continue;
            }

            match Regex::new(&rule.pattern) {
                Ok(pattern) => {
                    self.compiled.push(CompiledRule { rule, pattern });
                    loaded += 1;
                }
                Err(e) => {
                    self.errors.push(format!(
                        "Regex inválido na regra {}: {e}",
                        rule.id
                    ));
                }
            }
        }

        if loaded > 0 {
            // Log silencioso — caller decide se imprime
            let _ = loaded; // evita warning unused
        }
    }

    /// Erros de carregamento (não fatais — regras inválidas são ignoradas).
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Número de regras carregadas com sucesso.
    pub fn rule_count(&self) -> usize {
        self.compiled.len()
    }

    /// Aplica todas as regras a uma linha de código.
    ///
    /// # Parâmetros
    /// - `line`: linha de código (não trimmed — coluna é calculada no original)
    /// - `language`: linguagem detectada (ex: `Some("java")`)
    ///
    /// # Retorno
    /// Vec de matches (pode ser vazio se nenhuma regra casar).
    pub fn apply_to_line(
        &self,
        line:     &str,
        language: Option<&str>,
    ) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for compiled in &self.compiled {
            // Filtro de linguagem
            if !compiled.rule.languages.is_empty() {
                match language {
                    Some(lang) => {
                        let lang_lc = lang.to_ascii_lowercase();
                        if !compiled.rule.languages.iter()
                            .any(|l| l.to_ascii_lowercase() == lang_lc)
                        {
                            continue;
                        }
                    }
                    None => continue, // linguagem desconhecida não passa no filtro
                }
            }

            if let Some(m) = compiled.pattern.find(line) {
                matches.push(RuleMatch {
                    rule_id:        compiled.rule.id.clone(),
                    severity_str:   compiled.rule.severity.clone(),
                    title:          compiled.rule.title.clone(),
                    description:    compiled.rule.description.clone(),
                    recommendation: compiled.rule.recommendation.clone(),
                    column:         m.start() + 1,
                    matched_text:   m.as_str().to_string(),
                    is_taint_sink:  compiled.rule.taint_sink,
                });
            }
        }

        matches
    }

    /// Lista todas as regras carregadas (para `qsec rules list`).
    pub fn list_rules(&self) -> Vec<&YamlRule> {
        self.compiled.iter().map(|c| &c.rule).collect()
    }
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_yaml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", content).unwrap();
        f
    }

    #[test]
    fn test_load_valid_yaml() {
        let yaml = r#"
rules:
  - id: "TEST-001"
    severity: "HIGH"
    title: "Padrão de teste"
    description: "Descrição"
    recommendation: "Recomendação"
    pattern: "insecure_fn\\("
    languages: []
"#;
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());

        assert!(engine.errors().is_empty(), "Não deve ter erros: {:?}", engine.errors());
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn test_apply_to_line_matches() {
        let yaml = r#"
rules:
  - id: "TEST-002"
    severity: "CRITICAL"
    title: "Função insegura"
    description: "Uso de função insegura"
    recommendation: "Use função segura"
    pattern: "unsafe_crypto\\("
    languages: []
"#;
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());

        let matches = engine.apply_to_line("let x = unsafe_crypto(key);", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "TEST-002");
    }

    #[test]
    fn test_language_filter() {
        let yaml = r#"
rules:
  - id: "TEST-003"
    severity: "HIGH"
    title: "Padrão Python"
    description: "..."
    recommendation: "..."
    pattern: "hashlib\\.md5"
    languages: ["python"]
"#;
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());

        // Deve casar com Python
        let py = engine.apply_to_line("h = hashlib.md5(data)", Some("python"));
        assert_eq!(py.len(), 1);

        // Não deve casar com Java
        let java = engine.apply_to_line("h = hashlib.md5(data)", Some("java"));
        assert_eq!(java.len(), 0);

        // Sem linguagem — não passa no filtro
        let none = engine.apply_to_line("h = hashlib.md5(data)", None);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_invalid_yaml_does_not_panic() {
        let yaml = "this is: not: valid: yaml: at all :::";
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());
        assert!(!engine.errors().is_empty());
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_invalid_regex_skipped() {
        let yaml = r#"
rules:
  - id: "TEST-BAD"
    severity: "HIGH"
    title: "Regex ruim"
    description: "..."
    recommendation: "..."
    pattern: "["    # regex inválido
    languages: []
"#;
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());
        assert!(!engine.errors().is_empty());
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_empty_dir_returns_empty_engine() {
        let dir = tempfile::tempdir().unwrap();
        let engine = RuleEngine::load_from_dir(dir.path());
        assert_eq!(engine.rule_count(), 0);
        assert!(engine.errors().is_empty());
    }

    #[test]
    fn test_nonexistent_dir_returns_empty() {
        let engine = RuleEngine::load_from_dir(Path::new("/nonexistent/rules/dir"));
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_dangerous_rule_id_rejected() {
        let yaml = r#"
rules:
  - id: "../../etc/passwd"
    severity: "HIGH"
    title: "Path traversal ID"
    description: "..."
    recommendation: "..."
    pattern: "test"
    languages: []
"#;
        let file = write_yaml(yaml);
        let mut engine = RuleEngine::new();
        engine.load_file(file.path());
        assert!(!engine.errors().is_empty(), "ID perigoso deve ser rejeitado");
        assert_eq!(engine.rule_count(), 0);
    }
}
