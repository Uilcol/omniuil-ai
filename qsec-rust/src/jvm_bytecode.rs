//! OmniUil AI v6.0 — JVM Bytecode Analysis
//! Analisa arquivos .class e .jar sem código-fonte.
//!
//! Por que isso importa:
//! - Bibliotecas terceiras (.jar) não têm código-fonte disponível
//! - Dependências compiladas podem usar MD5/RSA sem que o desenvolvedor saiba
//! - Bancos e fintechs Java têm centenas de JARs em produção
//!
//! O que detecta:
//! - Referências a classes criptográficas fracas nas constant pools dos .class
//! - JARs que contêm algoritmos vulneráveis via análise de manifesto e strings
//! - Dependências transitivas com algoritmos PQC-vulneráveis
//!
//! Técnica: análise de strings UTF-8 nas constant pools dos bytecodes Java
//! sem executar o código — 100% estático, zero I/O de rede, zero unsafe.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::io::Read;

// ── Tipos ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeFinding {
    pub file:        String,   // .class ou .jar
    pub class_name:  String,   // nome da classe Java
    pub evidence:    String,   // string da constant pool que evidencia o problema
    pub algorithm:   String,   // algoritmo detectado
    pub severity:    String,
    pub rule_id:     String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarManifest {
    pub main_class:       Option<String>,
    pub implementation:   Option<String>,
    pub spec_version:     Option<String>,
    pub created_by:       Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeReport {
    pub file:               String,
    pub file_type:          String,   // "class" ou "jar"
    pub findings:           Vec<BytecodeFinding>,
    pub classes_analyzed:   usize,
    pub manifest:           Option<JarManifest>,
    pub summary:            String,
}

// ── Strings criptográficas que indicam vulnerabilidade ────────────────────────

/// Padrões de strings que aparecem nas constant pools de bytecodes Java
/// quando algoritmos criptográficos vulneráveis são usados
const WEAK_CRYPTO_STRINGS: &[(&str, &str, &str, &str, &str)] = &[
    // (padrão, algoritmo, severidade, rule_id, recomendação)
    ("MD5",
     "MD5", "HIGH", "QSC-JVM-001",
     "Substitua MessageDigest.getInstance(\"MD5\") por MessageDigest.getInstance(\"SHA3-256\")"),
    ("SHA-1",
     "SHA-1", "HIGH", "QSC-JVM-002",
     "Substitua por SHA3-256. SHA-1 quebrado desde 2017 (ataque SHAttered)"),
    ("SHA1",
     "SHA-1", "HIGH", "QSC-JVM-002",
     "Substitua por SHA3-256. SHA-1 quebrado desde 2017 (ataque SHAttered)"),
    ("DES",
     "DES/3DES", "CRITICAL", "QSC-JVM-003",
     "Substitua por AES-256-GCM. DES é quebrado classicamente"),
    ("DESede",
     "3DES", "CRITICAL", "QSC-JVM-003",
     "Substitua por AES-256-GCM. Triple-DES é vulnerável a meet-in-the-middle"),
    ("RC4",
     "RC4", "CRITICAL", "QSC-JVM-004",
     "Substitua por ChaCha20-Poly1305 ou AES-256-GCM. RC4 é quebrado"),
    ("Blowfish",
     "Blowfish", "HIGH", "QSC-JVM-005",
     "Substitua por AES-256-GCM. Blowfish tem vulnerabilidades conhecidas com blocos de 64 bits"),
    ("RSA",
     "RSA", "HIGH", "QSC-JVM-006",
     "RSA vulnerável ao algoritmo de Shor. Migrar para ML-KEM-768 (NIST FIPS 203) + ML-DSA-65 (FIPS 204)"),
    ("ECDSAwithSHA256",
     "ECDSA", "HIGH", "QSC-JVM-007",
     "ECDSA vulnerável ao algoritmo de Shor. Migrar para ML-DSA-65 (NIST FIPS 204)"),
    ("SHA256withRSA",
     "RSA", "HIGH", "QSC-JVM-006",
     "RSA com SHA-256 ainda vulnerável a Shor. Migrar para ML-DSA-65"),
    ("SHA1withRSA",
     "RSA+SHA1", "CRITICAL", "QSC-JVM-008",
     "SHA-1 + RSA: duplamente vulnerável. Substituição urgente por ML-DSA-65"),
    ("MD5withRSA",
     "RSA+MD5", "CRITICAL", "QSC-JVM-008",
     "MD5 + RSA: duplamente vulnerável e classicamente quebrado. Substituição imediata"),
    ("AES/CBC/PKCS5Padding",
     "AES-CBC", "MEDIUM", "QSC-JVM-009",
     "AES-CBC vulnerável a padding oracle attacks. Use AES/GCM/NoPadding"),
    ("AES/ECB",
     "AES-ECB", "CRITICAL", "QSC-JVM-010",
     "AES-ECB não deve ser usado — não garante confidencialidade. Use AES/GCM/NoPadding"),
    ("javax/crypto/SecretKeyFactory",
     "SecretKeyFactory", "MEDIUM", "QSC-JVM-011",
     "Verificar algoritmo usado com SecretKeyFactory — PBEWithMD5AndDES é vulnerável"),
    ("PBEWithMD5AndDES",
     "PBE-MD5-DES", "CRITICAL", "QSC-JVM-012",
     "PBEWithMD5AndDES é duplamente vulnerável. Use AES-256-GCM com Argon2id para derivação de chave"),
    ("java/security/MessageDigest",
     "MessageDigest", "LOW", "QSC-JVM-013",
     "Classe MessageDigest detectada — verificar algoritmo usado no contexto"),
    ("javax/net/ssl/SSLContext",
     "SSLContext", "LOW", "QSC-JVM-014",
     "SSLContext detectado — verificar versão TLS configurada (mínimo TLS 1.3)"),
    ("SSLv3",
     "SSLv3", "CRITICAL", "QSC-JVM-015",
     "SSLv3 é quebrado (ataque POODLE 2014). Desabilitar imediatamente, usar TLS 1.3"),
    ("TLSv1.0",
     "TLS 1.0", "HIGH", "QSC-JVM-016",
     "TLS 1.0 é inseguro (BEAST, POODLE). Configurar mínimo TLS 1.3"),
    ("TLSv1.1",
     "TLS 1.1", "HIGH", "QSC-JVM-016",
     "TLS 1.1 é inseguro. Configurar mínimo TLS 1.3"),
];

// ── Magic bytes para identificar formato ─────────────────────────────────────

const CLASS_MAGIC: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
const JAR_MAGIC:   &[u8] = &[0x50, 0x4B, 0x03, 0x04];  // ZIP/JAR

// ── Análise de .class ─────────────────────────────────────────────────────────

/// Extrai strings UTF-8 da constant pool de um arquivo .class
/// sem precisar fazer parse completo do bytecode
fn extract_class_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();

    // Verifica magic bytes do .class
    if data.len() < 8 || &data[0..4] != CLASS_MAGIC {
        return strings;
    }

    // Pula header: magic (4) + minor_version (2) + major_version (2)
    // Depois vem constant_pool_count (u16) e as entradas da constant pool
    if data.len() < 10 { return strings; }

    let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut pos = 10usize;

    for _ in 1..cp_count {
        if pos >= data.len() { break; }

        let tag = data[pos];
        pos += 1;

        match tag {
            // CONSTANT_Utf8 (tag=1): length (u16) + bytes
            1 => {
                if pos + 2 > data.len() { break; }
                let len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
                pos += 2;
                if pos + len > data.len() { break; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos+len]) {
                    let s = s.to_string();
                    // Filtra strings relevantes para análise crypto
                    if s.len() >= 3 && s.len() <= 200 &&
                       (s.contains("MD5") || s.contains("SHA") || s.contains("RSA") ||
                        s.contains("AES") || s.contains("DES") || s.contains("RC4") ||
                        s.contains("TLS") || s.contains("SSL") || s.contains("cipher") ||
                        s.contains("Cipher") || s.contains("crypto") ||
                        s.contains("javax/crypto") || s.contains("java/security") ||
                        s.contains("Blowfish") || s.contains("PBE") ||
                        s.contains("ECDSAwith") || s.contains("withRSA")) {
                        strings.push(s);
                    }
                }
                pos += len;
            },
            // CONSTANT_Class (tag=7): name_index (u16)
            7  => { pos += 2; },
            // CONSTANT_String (tag=8): string_index (u16)
            8  => { pos += 2; },
            // CONSTANT_Fieldref, Methodref, InterfaceMethodref (tags 9,10,11)
            9 | 10 | 11 => { pos += 4; },
            // CONSTANT_Integer, Float (tags 3,4)
            3 | 4 => { pos += 4; },
            // CONSTANT_Long, Double (tags 5,6) — ocupam 2 slots
            5 | 6 => {
                pos += 8;
                // Long e Double ocupam dois slots na constant pool
                break; // simplificação — pula o resto se encontrar long/double
            },
            // CONSTANT_NameAndType (tag=12)
            12 => { pos += 4; },
            // CONSTANT_MethodHandle (tag=15)
            15 => { pos += 3; },
            // CONSTANT_MethodType (tag=16)
            16 => { pos += 2; },
            // CONSTANT_InvokeDynamic (tag=18)
            18 => { pos += 4; },
            // Desconhecido — para de parsear
            _ => { break; }
        }
    }

    strings
}

/// Analisa um arquivo .class
pub fn analyze_class_file(path: &Path, data: &[u8]) -> Vec<BytecodeFinding> {
    let mut findings = Vec::new();
    let path_str = path.display().to_string();

    // Extrai nome da classe do caminho
    let class_name = path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    // Extrai strings da constant pool
    let strings = extract_class_strings(data);

    for string in &strings {
        for (pattern, algorithm, severity, rule_id, recommendation) in WEAK_CRYPTO_STRINGS {
            if string.contains(pattern) {
                // Evita duplicatas
                let already = findings.iter().any(|f: &BytecodeFinding|
                    f.rule_id == *rule_id && f.evidence == *string);
                if !already {
                    findings.push(BytecodeFinding {
                        file:        path_str.clone(),
                        class_name:  class_name.clone(),
                        evidence:    string.clone(),
                        algorithm:   algorithm.to_string(),
                        severity:    severity.to_string(),
                        rule_id:     rule_id.to_string(),
                        description: format!(
                            "Algoritmo {} detectado na constant pool da classe {}",
                            algorithm, class_name
                        ),
                        recommendation: recommendation.to_string(),
                    });
                }
            }
        }
    }

    findings
}

// ── Análise de .jar ───────────────────────────────────────────────────────────

/// Analisa um arquivo .jar (ZIP com arquivos .class dentro)
pub fn analyze_jar_file(path: &Path, data: &[u8]) -> BytecodeReport {
    let path_str = path.display().to_string();
    let mut all_findings = Vec::new();
    let mut classes_analyzed = 0usize;
    let mut manifest: Option<JarManifest> = None;

    // Verifica magic bytes do JAR/ZIP
    if data.len() < 4 || &data[0..4] != JAR_MAGIC {
        return BytecodeReport {
            file: path_str, file_type: "jar".to_string(),
            findings: vec![], classes_analyzed: 0,
            manifest: None,
            summary: "Arquivo não é um JAR/ZIP válido".to_string(),
        };
    }

    // Parse simplificado do ZIP: procura por entradas usando o directory central
    // Técnica: busca pelo magic PK\x03\x04 (local file header) e extrai nomes
    let mut pos = 0usize;
    while pos + 30 < data.len() {
        // Procura local file header: PK\x03\x04
        if &data[pos..pos+4] == b"PK\x03\x04" {
            if pos + 30 > data.len() { break; }

            // Parse do local file header
            let compression   = u16::from_le_bytes([data[pos+8],  data[pos+9]]);
            let comp_size     = u32::from_le_bytes([data[pos+18], data[pos+19],
                                                    data[pos+20], data[pos+21]]) as usize;
            let uncomp_size   = u32::from_le_bytes([data[pos+22], data[pos+23],
                                                    data[pos+24], data[pos+25]]) as usize;
            let fname_len     = u16::from_le_bytes([data[pos+26], data[pos+27]]) as usize;
            let extra_len     = u16::from_le_bytes([data[pos+28], data[pos+29]]) as usize;

            let fname_start   = pos + 30;
            let fname_end     = fname_start + fname_len;
            let data_start    = fname_end + extra_len;

            if fname_end > data.len() { break; }

            let filename = std::str::from_utf8(&data[fname_start..fname_end])
                .unwrap_or("").to_string();

            // Processa MANIFEST.MF
            if filename == "META-INF/MANIFEST.MF" && compression == 0 {
                let data_end = data_start + uncomp_size.min(data.len() - data_start);
                if data_start < data.len() {
                    let manifest_text = std::str::from_utf8(&data[data_start..data_end])
                        .unwrap_or("");
                    manifest = Some(parse_manifest(manifest_text));
                }
            }

            // Processa arquivos .class não comprimidos
            if filename.ends_with(".class") && compression == 0 {
                let data_end = data_start + uncomp_size.min(data.len() - data_start);
                if data_start < data.len() && data_end <= data.len() {
                    let class_data = &data[data_start..data_end];
                    let class_path = Path::new(&filename);
                    let mut class_findings = analyze_class_file(class_path, class_data);
                    // Atualiza file para mostrar jar!class
                    for f in &mut class_findings {
                        f.file = format!("{}!{}", path_str, filename);
                    }
                    all_findings.extend(class_findings);
                    classes_analyzed += 1;
                }
            }

            // Avança para próxima entrada
            let entry_size = 30 + fname_len + extra_len + comp_size;
            if entry_size == 0 { pos += 1; } else { pos += entry_size; }
        } else {
            pos += 1;
        }
    }

    // Se não encontrou .class, faz análise de strings direta no JAR
    // (para JARs com classes comprimidas)
    if classes_analyzed == 0 {
        let jar_strings = extract_strings_from_binary(data);
        for string in &jar_strings {
            for (pattern, algorithm, severity, rule_id, recommendation) in WEAK_CRYPTO_STRINGS {
                if string.contains(pattern) {
                    let already = all_findings.iter().any(|f: &BytecodeFinding|
                        f.rule_id == *rule_id);
                    if !already {
                        all_findings.push(BytecodeFinding {
                            file:        path_str.clone(),
                            class_name:  "unknown (JAR comprimido)".to_string(),
                            evidence:    string.clone(),
                            algorithm:   algorithm.to_string(),
                            severity:    severity.to_string(),
                            rule_id:     rule_id.to_string(),
                            description: format!(
                                "Algoritmo {} detectado via análise de strings no JAR (classes comprimidas)",
                                algorithm
                            ),
                            recommendation: recommendation.to_string(),
                        });
                    }
                }
            }
        }
    }

    let n = all_findings.len();
    let summary = format!(
        "{} classes analisadas, {} finding(s) detectado(s) em {}",
        classes_analyzed, n,
        path.file_name().and_then(|f| f.to_str()).unwrap_or("")
    );

    BytecodeReport {
        file: path_str,
        file_type: "jar".to_string(),
        findings: all_findings,
        classes_analyzed,
        manifest,
        summary,
    }
}

/// Extrai strings ASCII/UTF-8 de binário (fallback para JARs comprimidos)
fn extract_strings_from_binary(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b'/' || byte == b'.' {
            current.push(byte as char);
        } else {
            if current.len() >= 4 {
                let relevant = current.contains("MD5") || current.contains("SHA")
                    || current.contains("RSA") || current.contains("DES")
                    || current.contains("AES") || current.contains("TLS")
                    || current.contains("SSL") || current.contains("RC4")
                    || current.contains("Cipher") || current.contains("crypto");
                if relevant {
                    strings.push(current.clone());
                }
            }
            current.clear();
        }
    }
    strings
}

fn parse_manifest(text: &str) -> JarManifest {
    let mut m = JarManifest {
        main_class: None, implementation: None,
        spec_version: None, created_by: None,
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Main-Class: ")         { m.main_class       = Some(v.trim().to_string()); }
        if let Some(v) = line.strip_prefix("Implementation-Title: "){ m.implementation   = Some(v.trim().to_string()); }
        if let Some(v) = line.strip_prefix("Specification-Version: "){ m.spec_version   = Some(v.trim().to_string()); }
        if let Some(v) = line.strip_prefix("Created-By: ")         { m.created_by       = Some(v.trim().to_string()); }
    }
    m
}

// ── Ponto de entrada público ──────────────────────────────────────────────────

/// Analisa um arquivo .class ou .jar
pub fn analyze_bytecode(path: &Path) -> BytecodeReport {
    let path_str = path.display().to_string();

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return BytecodeReport {
            file: path_str, file_type: "unknown".to_string(),
            findings: vec![], classes_analyzed: 0, manifest: None,
            summary: format!("Erro ao ler arquivo: {}", e),
        },
    };

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "class" => {
            let findings = analyze_class_file(path, &data);
            let n = findings.len();
            BytecodeReport {
                file: path_str, file_type: "class".to_string(),
                classes_analyzed: 1,
                summary: format!("{} finding(s) em {}", n,
                    path.file_name().and_then(|f| f.to_str()).unwrap_or("")),
                findings, manifest: None,
            }
        },
        "jar" | "war" | "ear" => analyze_jar_file(path, &data),
        _ => BytecodeReport {
            file: path_str, file_type: ext.to_string(),
            findings: vec![], classes_analyzed: 0, manifest: None,
            summary: format!("Formato não suportado: .{}", ext),
        },
    }
}

/// Analisa um diretório recursivamente buscando .class e .jar
pub fn analyze_bytecode_directory(dir: &Path) -> Vec<BytecodeReport> {
    let mut reports = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                reports.extend(analyze_bytecode_directory(&path));
            } else {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "class" | "jar" | "war" | "ear") {
                    reports.push(analyze_bytecode(path.as_path()));
                }
            }
        }
    }

    reports
}

pub fn bytecode_to_json(reports: &[BytecodeReport]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "analysis_type": "jvm_bytecode",
        "total_files":   reports.len(),
        "total_findings": reports.iter().map(|r| r.findings.len()).sum::<usize>(),
        "reports": reports,
    })).unwrap_or_else(|_| "{}".to_string())
}
