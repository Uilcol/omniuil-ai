//! OmniUil AI — Crypto Knowledge Graph
//! Fusão do Paralax v0.2.0: grafo de inteligência criptográfica
//!
//! Modela relações entre: algoritmos, arquivos, certificados, riscos e migrações.
//! Permite responder: "qual é o impacto de migrar RSA neste sistema?"
//!
//! Zero unsafe code. Determinístico. Sem I/O de rede.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::scanner::CryptoFinding;

// ── Tipos do grafo ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Algorithm,    // Nó de algoritmo criptográfico (RSA, AES, etc.)
    File,         // Arquivo de código-fonte
    Certificate,  // Certificado X.509
    Service,      // Serviço ou componente
    Rule,         // Regra PQC que disparou
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    Uses,           // arquivo usa algoritmo
    Implements,     // serviço implementa algoritmo
    References,     // arquivo referencia certificado
    MigratesTo,     // algoritmo migra para algoritmo PQC
    DetectedBy,     // algoritmo foi detectado por regra
    CoLocated,      // dois algoritmos no mesmo arquivo (risco de inconsistência)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id:          String,
    pub node_type:   NodeType,
    pub label:       String,
    pub properties:  HashMap<String, String>,
    pub risk_score:  u32,   // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from:      String,
    pub to:        String,
    pub edge_type: EdgeType,
    pub weight:    f32,     // relevância da relação
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoGraph {
    pub nodes:     Vec<GraphNode>,
    pub edges:     Vec<GraphEdge>,
    pub summary:   GraphSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub total_nodes:           usize,
    pub total_edges:           usize,
    pub algorithm_nodes:       usize,
    pub file_nodes:            usize,
    pub vulnerable_algorithms: usize,
    pub migration_paths:       usize,
    pub highest_risk_node:     Option<String>,
    pub migration_priority:    Vec<String>,
}

// ── Algoritmos e seus targets de migração PQC ─────────────────────────────────
fn migration_target(algorithm: &str) -> Option<&'static str> {
    match algorithm.to_uppercase().as_str() {
        a if a.contains("RSA")   => Some("ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204)"),
        a if a.contains("ECDSA") => Some("ML-DSA-65 (NIST FIPS 204)"),
        a if a.contains("ECDH")  => Some("ML-KEM-768 (NIST FIPS 203)"),
        a if a.contains("DH")    => Some("ML-KEM-768 (NIST FIPS 203)"),
        a if a.contains("MD5")   => Some("SHA3-256 ou BLAKE2b"),
        a if a.contains("SHA-1") => Some("SHA3-256 (NIST FIPS 202)"),
        a if a.contains("SHA1")  => Some("SHA3-256 (NIST FIPS 202)"),
        a if a.contains("AES-128") => Some("AES-256-GCM"),
        a if a.contains("DES")   => Some("AES-256-GCM"),
        a if a.contains("RC4")   => Some("ChaCha20-Poly1305"),
        _ => None,
    }
}

fn algorithm_risk(rule_id: &str) -> u32 {
    match rule_id {
        r if r.contains("QSC-001") || r.contains("QSC-002") ||
             r.contains("QSC-020") || r.contains("QSC-022") => 95,
        r if r.contains("QSC-003") || r.contains("QSC-014") ||
             r.contains("QSC-116") => 90,
        r if r.contains("QSC-010") || r.contains("QSC-011") ||
             r.contains("QSC-013") => 80,
        r if r.contains("QSC-030") || r.contains("QSC-108") => 75,
        r if r.contains("QSC-012") || r.contains("QSC-104") => 60,
        r if r.contains("QSC-200") || r.contains("QSC-201") => 40,
        _ => 30,
    }
}

// ── Construção do grafo ───────────────────────────────────────────────────────

pub fn build_crypto_graph(findings: &[CryptoFinding]) -> CryptoGraph {
    let mut nodes: HashMap<String, GraphNode> = HashMap::new();
    let mut edges: Vec<GraphEdge> = Vec::new();

    // 1. Cria nós de algoritmo e arquivo
    for f in findings {
        let alg_id  = format!("alg:{}", f.rule_id);
        let file_id = format!("file:{}", sanitize_id(&f.file));
        let risk    = algorithm_risk(&f.rule_id);

        // Nó do algoritmo
        nodes.entry(alg_id.clone()).or_insert_with(|| {
            let mut props = HashMap::new();
            props.insert("rule_id".to_string(),    f.rule_id.clone());
            props.insert("severity".to_string(),   format!("{:?}", f.severity));
            props.insert("risk_score".to_string(), risk.to_string());
            if let Some(target) = migration_target(&f.title) {
                props.insert("migration_target".to_string(), target.to_string());
            }
            GraphNode {
                id:         alg_id.clone(),
                node_type:  NodeType::Algorithm,
                label:      f.title.clone(),
                properties: props,
                risk_score: risk,
            }
        });

        // Nó do arquivo
        nodes.entry(file_id.clone()).or_insert_with(|| {
            let mut props = HashMap::new();
            props.insert("path".to_string(), f.file.clone());
            GraphNode {
                id:         file_id.clone(),
                node_type:  NodeType::File,
                label:      f.file.split('/').last().unwrap_or(&f.file).to_string(),
                properties: props,
                risk_score: risk,
            }
        });

        // Nó da regra
        let rule_id_node = format!("rule:{}", f.rule_id);
        nodes.entry(rule_id_node.clone()).or_insert_with(|| {
            GraphNode {
                id:         rule_id_node.clone(),
                node_type:  NodeType::Rule,
                label:      f.rule_id.clone(),
                properties: HashMap::new(),
                risk_score: risk,
            }
        });

        // Arestas
        edges.push(GraphEdge {
            from:      file_id.clone(),
            to:        alg_id.clone(),
            edge_type: EdgeType::Uses,
            weight:    risk as f32 / 100.0,
        });
        edges.push(GraphEdge {
            from:      alg_id.clone(),
            to:        rule_id_node,
            edge_type: EdgeType::DetectedBy,
            weight:    1.0,
        });

        // Aresta de migração (se existe target PQC)
        if let Some(target) = migration_target(&f.title) {
            let target_id = format!("alg:pqc:{}", sanitize_id(target));
            nodes.entry(target_id.clone()).or_insert_with(|| {
                let mut props = HashMap::new();
                props.insert("status".to_string(), "PQC_APPROVED".to_string());
                props.insert("nist_status".to_string(), "FIPS_FINAL".to_string());
                GraphNode {
                    id:         target_id.clone(),
                    node_type:  NodeType::Algorithm,
                    label:      target.to_string(),
                    properties: props,
                    risk_score: 0,
                }
            });
            edges.push(GraphEdge {
                from:      alg_id.clone(),
                to:        target_id,
                edge_type: EdgeType::MigratesTo,
                weight:    1.0,
            });
        }
    }

    // 2. Detecta co-localização (múltiplos algoritmos no mesmo arquivo)
    let mut file_algorithms: HashMap<String, Vec<String>> = HashMap::new();
    for f in findings {
        let file_id = format!("file:{}", sanitize_id(&f.file));
        let alg_id  = format!("alg:{}", f.rule_id);
        file_algorithms.entry(file_id).or_default().push(alg_id);
    }
    for (file_id, algs) in &file_algorithms {
        if algs.len() > 1 {
            for i in 0..algs.len()-1 {
                edges.push(GraphEdge {
                    from:      algs[i].clone(),
                    to:        algs[i+1].clone(),
                    edge_type: EdgeType::CoLocated,
                    weight:    0.5,
                });
            }
        }
    }

    // 3. Calcula sumário
    let nodes_vec: Vec<GraphNode> = nodes.into_values().collect();
    let alg_nodes: Vec<&GraphNode> = nodes_vec.iter()
        .filter(|n| n.node_type == NodeType::Algorithm && n.risk_score > 0).collect();
    let file_nodes = nodes_vec.iter().filter(|n| n.node_type == NodeType::File).count();
    let vulnerable = alg_nodes.iter().filter(|n| n.risk_score >= 70).count();
    let migration_paths = edges.iter().filter(|e| matches!(e.edge_type, EdgeType::MigratesTo)).count();

    let highest_risk = alg_nodes.iter().max_by_key(|n| n.risk_score)
        .map(|n| n.label.clone());

    let mut priority: Vec<String> = alg_nodes.iter()
        .filter(|n| n.risk_score >= 70)
        .map(|n| format!("{} (risk:{})", n.label, n.risk_score))
        .collect();
    priority.sort_by(|a,b| b.cmp(a));
    priority.truncate(5);

    let summary = GraphSummary {
        total_nodes:           nodes_vec.len(),
        total_edges:           edges.len(),
        algorithm_nodes:       alg_nodes.len(),
        file_nodes,
        vulnerable_algorithms: vulnerable,
        migration_paths,
        highest_risk_node:     highest_risk,
        migration_priority:    priority,
    };

    CryptoGraph { nodes: nodes_vec, edges, summary }
}

fn sanitize_id(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

pub fn graph_to_json(graph: &CryptoGraph) -> String {
    serde_json::to_string_pretty(graph).unwrap_or_else(|_| "{}".to_string())
}
