//! # Grafo de Evidência — Absorção do OmniUil AI
//!
//! Fornece contexto de código ao redor de cada finding:
//!   - Linhas antes e depois do ponto vulnerável
//!   - Destaque da linha exata com marcador
//!   - Conexão visual fonte→sink para taint findings
//!
//! Este módulo substitui a exibição simples de snippet de uma linha
//! por um contexto completo que explica visualmente por que o código
//! é vulnerável — o "Grafo de Evidência" do OmniUil AI.
//!
//! ## Exemplo de saída
//!
//! ```text
//! ┌─ Evidência: QSC-001 (CRITICAL) ─────────────────────────────────────┐
//! │ src/crypto.rs
//! │  42 │   let config = load_config();
//! │  43 │   let rsa_size = config.key_size;
//! │► 44 │   let key = RSA::generate(rsa_size);   ← VULNERÁVEL
//! │  45 │   sign_artifact(&artifact, &key);
//! │  46 │ }
//! └──────────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};

use crate::taint::TaintFinding;

/// Número de linhas de contexto antes e depois do finding.
const CONTEXT_LINES: usize = 3;

/// Uma linha com seu número e conteúdo, mais indicador se é a linha do finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextLine {
    /// Número da linha (1-indexed)
    pub line_number: usize,
    /// Conteúdo da linha
    pub content: String,
    /// Se esta é a linha exatamente onde o finding foi detectado
    pub is_finding_line: bool,
}

/// Contexto de evidência para um finding individual.
///
/// Contém as linhas ao redor do finding e metadados para renderização.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceContext {
    /// Arquivo de origem
    pub file: String,
    /// Linha do finding (1-indexed)
    pub finding_line: usize,
    /// Coluna do finding (1-indexed)
    pub finding_column: usize,
    /// ID da regra (ex: "QSC-001")
    pub rule_id: String,
    /// Severidade como string
    pub severity: String,
    /// Título do finding
    pub title: String,
    /// Linhas de contexto (inclui a linha do finding + N ao redor)
    pub context_lines: Vec<ContextLine>,
    /// Para findings de taint: descreve o fluxo fonte→sink
    pub taint_flow: Option<TaintFlow>,
}

/// Fluxo de taint: descreve de onde o dado veio e para onde foi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Linha onde o dado externo entrou (fonte)
    pub source_line: usize,
    /// Código da fonte
    pub source_code: String,
    /// Tipo da fonte (env var, HTTP request, etc.)
    pub source_type: String,
    /// Nome da variável contaminada
    pub var_name: String,
    /// Linha do sink (onde o dado contaminado é usado em crypto)
    pub sink_line: usize,
    /// Código do sink
    pub sink_code: String,
}

/// Grafo de evidências: coleção de contextos para todos os findings de um scan.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EvidenceGraph {
    /// Contextos de findings de scanner
    pub scanner_evidence: Vec<EvidenceContext>,
    /// Contextos de findings de taint
    pub taint_evidence: Vec<EvidenceContext>,
}

impl EvidenceGraph {
    /// Cria um grafo vazio.
    pub fn new() -> Self {
        Self::default()
    }

    /// Constrói evidências para um finding do scanner.
    ///
    /// Aceita campos primitivos para evitar dependência circular com `scanner.rs`.
    pub fn add_scanner_finding(
        &mut self,
        file:     &str,
        line:     usize,
        column:   usize,
        rule_id:  &str,
        severity: &str,
        title:    &str,
    ) {
        let ctx = build_evidence_from_file(
            file, line, column, rule_id, severity, title, None,
        );
        self.scanner_evidence.push(ctx);
    }

    /// Constrói evidências para um finding de taint.
    pub fn add_taint_finding(&mut self, finding: &TaintFinding) {
        let taint_flow = Some(TaintFlow {
            source_line: finding.path.source_line,
            source_code: finding.path.source_code.clone(),
            source_type: finding.path.source_type.to_string(),
            var_name:    finding.path.var_name.clone(),
            sink_line:   finding.path.sink_line,
            sink_code:   finding.path.sink_code.clone(),
        });

        let ctx = build_evidence_from_file(
            &finding.file,
            finding.path.sink_line,
            1,
            &finding.rule_id,
            "HIGH",
            &finding.title,
            taint_flow,
        );
        self.taint_evidence.push(ctx);
    }

    /// Retorna todos os contextos (scanner + taint) ordenados por arquivo e linha.
    pub fn all_contexts(&self) -> Vec<&EvidenceContext> {
        let mut all: Vec<&EvidenceContext> = self.scanner_evidence.iter()
            .chain(self.taint_evidence.iter())
            .collect();
        all.sort_by(|a, b| {
            a.file.cmp(&b.file).then(a.finding_line.cmp(&b.finding_line))
        });
        all
    }

    /// Formata o grafo completo como texto para exibição no terminal.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let all = self.all_contexts();

        if all.is_empty() {
            return out;
        }

        out.push_str("\n╔══════════════════════════════════════════════════════════════╗\n");
        out.push_str("║              QSEC — Grafo de Evidências (OmniUil AI)         ║\n");
        out.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

        for ctx in all {
            render_evidence_context(&mut out, ctx);
        }

        out
    }
}

// ─── Funções internas ─────────────────────────────────────────────────────────

/// Constrói um EvidenceContext lendo o arquivo para extrair linhas de contexto.
fn build_evidence_from_file(
    file:         &str,
    finding_line: usize,
    column:       usize,
    rule_id:      &str,
    severity:     &str,
    title:        &str,
    taint_flow:   Option<TaintFlow>,
) -> EvidenceContext {
    let context_lines = read_context_lines(file, finding_line);
    EvidenceContext {
        file:            file.to_string(),
        finding_line,
        finding_column:  column,
        rule_id:         rule_id.to_string(),
        severity:        severity.to_string(),
        title:           title.to_string(),
        context_lines,
        taint_flow,
    }
}

/// Lê CONTEXT_LINES antes e depois da linha do finding.
/// Retorna Vec vazio se o arquivo não puder ser lido (finding ainda é válido).
fn read_context_lines(file: &str, finding_line: usize) -> Vec<ContextLine> {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let all_lines: Vec<&str> = content.lines().collect();
    let total = all_lines.len();

    if finding_line == 0 || finding_line > total {
        return Vec::new();
    }

    // finding_line é 1-indexed → índice = finding_line - 1
    let idx = finding_line - 1;
    let start = idx.saturating_sub(CONTEXT_LINES);
    let end   = (idx + CONTEXT_LINES + 1).min(total);

    let mut result = Vec::new();
    for i in start..end {
        // Limita linha a 200 chars para evitar linhas geradas muito longas
        let content_str = all_lines[i];
        // Trunca respeitando limites de char UTF-8
        let content_truncated: String;
        let content_str = if content_str.chars().count() > 200 {
            content_truncated = content_str.chars().take(200).collect();
            content_truncated.as_str()
        } else {
            content_str
        };

        result.push(ContextLine {
            line_number:    i + 1,
            content:        content_str.to_string(),
            is_finding_line: i == idx,
        });
    }

    result
}

/// Renderiza um único EvidenceContext como bloco de texto.
fn render_evidence_context(out: &mut String, ctx: &EvidenceContext) {
    let header = format!(
        "┌─ {} ({}) ─ {} ",
        ctx.rule_id, ctx.severity, ctx.title
    );
    // Alinha o cabeçalho com ─ até 72 chars
    let header_padded = format!("{:─<72}┐", header);
    out.push_str(&header_padded);
    out.push('\n');

    // Nome do arquivo
    out.push_str(&format!("│ 📄 {}\n", ctx.file));

    if ctx.context_lines.is_empty() {
        out.push_str("│ (arquivo não disponível para leitura de contexto)\n");
    } else {
        for cl in &ctx.context_lines {
            let marker = if cl.is_finding_line { "►" } else { " " };
            let line_str = format!(
                "│{} {:>4} │ {}",
                marker, cl.line_number, cl.content
            );
            // Trunca se muito longo — respeitando limites de char UTF-8
            let line_str = if line_str.chars().count() > 78 {
                let truncated: String = line_str.chars().take(77).collect();
                format!("{}…", truncated)
            } else {
                line_str
            };
            out.push_str(&line_str);
            if cl.is_finding_line {
                out.push_str("  ← VULNERÁVEL");
            }
            out.push('\n');
        }
    }

    // Fluxo de taint (se disponível)
    if let Some(tf) = &ctx.taint_flow {
        out.push_str("│\n");
        out.push_str(&format!(
            "│  🔴 TAINT FLOW: '{}' ({}) linha {} → sink linha {}\n",
            tf.var_name, tf.source_type, tf.source_line, tf.sink_line
        ));
        out.push_str(&format!("│     Origem:  {}\n", tf.source_code));
        out.push_str(&format!("│     Sink:    {}\n", tf.sink_code));
    }

    out.push_str(&"└".to_string());
    out.push_str(&"─".repeat(72));
    out.push_str("┘\n\n");
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_temp_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{}", content).unwrap();
        f
    }

    #[test]
    fn test_read_context_lines_center() {
        let code = "line1\nline2\nline3\nline4\nline5\nline6\nline7\n";
        let f = make_temp_file(code);
        let path = f.path().to_str().unwrap();

        // Finding na linha 4 → deve retornar linhas 1..7 (ou subset)
        let lines = read_context_lines(path, 4);
        assert!(!lines.is_empty());

        // A linha 4 deve ser marcada como finding
        let finding = lines.iter().find(|l| l.is_finding_line).unwrap();
        assert_eq!(finding.line_number, 4);
        assert_eq!(finding.content, "line4");
    }

    #[test]
    fn test_read_context_lines_at_start() {
        let code = "line1\nline2\nline3\n";
        let f = make_temp_file(code);
        let path = f.path().to_str().unwrap();

        // Finding na linha 1 → não deve entrar em pânico com underflow
        let lines = read_context_lines(path, 1);
        assert!(!lines.is_empty());
        assert!(lines[0].is_finding_line);
    }

    #[test]
    fn test_read_context_lines_missing_file() {
        let lines = read_context_lines("/nao/existe/arquivo.rs", 5);
        assert!(lines.is_empty(), "Arquivo ausente deve retornar Vec vazio");
    }

    #[test]
    fn test_evidence_graph_render_not_empty() {
        let graph = EvidenceGraph::new();
        // Grafo vazio → render não panics
        let rendered = graph.render_text();
        assert!(rendered.is_empty() || rendered.contains("QSEC"));
    }

    #[test]
    fn test_evidence_context_with_taint_flow() {
        let ctx = EvidenceContext {
            file:           "test.rs".to_string(),
            finding_line:   5,
            finding_column: 1,
            rule_id:        "TAINT-001".to_string(),
            severity:       "HIGH".to_string(),
            title:          "Taint flow test".to_string(),
            context_lines:  vec![],
            taint_flow:     Some(TaintFlow {
                source_line: 2,
                source_code: "let algo = env::var(\"ALG\").unwrap();".to_string(),
                source_type: "variável de ambiente".to_string(),
                var_name:    "algo".to_string(),
                sink_line:   5,
                sink_code:   "Cipher::new(algo)".to_string(),
            }),
        };

        let mut out = String::new();
        render_evidence_context(&mut out, &ctx);
        assert!(out.contains("TAINT FLOW"));
        assert!(out.contains("algo"));
    }
}
