//! # QSEC — Post-Quantum Cryptographic Firewall
//!
//! Infraestrutura de confiança criptográfica para a era da computação quântica.
//!
//! ## Os 5 Pilares (v3.3 — Absorção OmniUil AI)
//!
//! | Pilar | Módulo | Função |
//! |-------|--------|--------|
//! | Crypto Scanner | [`scanner`] | Detecta RSA, ECDSA, MD5, SHA-1, JWT inseguro... |
//! | PQC Engine | [`pqc_engine`] | X25519+ML-KEM, Ed25519+ML-DSA, AES-256-GCM |
//! | Supply Chain | [`supply_chain`] | SBOM CycloneDX 1.5, Artifact Signing, Attestation |
//! | Zero Trust | [`zero_trust`] | PQC-JWT, KeyRegistry, APIKeyManager |
//! | OmniUil Absorção | [`languages`] + [`rules`] + [`taint`] + [`evidence`] | Adaptadores de linguagem, regras YAML, análise de taint, grafo de evidência |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use qsec::QsecPlatform;
//! use std::path::Path;
//!
//! let mut platform = QsecPlatform::new().expect("init failed");
//!
//! // Scan de crypto fraca
//! let report = platform.scan(Path::new("./src")).expect("scan failed");
//!
//! // PQC-JWT
//! let token = platform.jwt_issue("alice@example.com", Default::default(), 3600, "api.example.com")
//!     .expect("issue failed");
//! let claims = platform.jwt_verify(&token, "api.example.com")
//!     .expect("verify failed");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod config;
pub mod error;
pub mod evidence;
pub mod languages;
pub mod pqc_engine;
pub mod rules;
pub mod sarif;
pub mod scanner;
pub mod supply_chain;
pub mod taint;
pub mod zero_trust;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

pub use config::QsecConfig;
pub use error::{QsecError, QsecResult};
pub use evidence::{EvidenceContext, EvidenceGraph};
pub use languages::{detect_language, Language};
pub use pqc_engine::{
    DsaPublicKey, EngineInfo, HybridCiphertext, HybridDsaKeyPair, HybridKemKeyPair,
    HybridSignature, KemPublicKey, PqcEngine,
};
pub use rules::{RuleEngine, RuleMatch, YamlRule};
pub use scanner::{CryptoFinding, CryptoScanner, Severity, SeverityCounts};
pub use supply_chain::{
    ArtifactManifest, ArtifactSigner, AttestationBuilder, BuildAttestation,
    Sbom, SbomGenerator, SignedArtifact,
};
pub use taint::{TaintAnalyzer, TaintFinding, TaintPath, TaintSourceType};
pub use zero_trust::{
    ApiKeyInfo, ApiKeyManager, JwtClaims, KeyRegistry, KeyStatusReport, PqcJwtManager,
};

/// Versão da plataforma QSEC.
pub const VERSION: &str = "3.3.0";

// ─── PLATAFORMA PRINCIPAL ─────────────────────────────────────────────────────

/// Ponto de entrada único para todos os subsistemas QSEC.
///
/// Orquestra os 4 pilares: Scanner, PQC Engine, Supply Chain e Zero Trust.
///
/// # Exemplo
///
/// ```rust,no_run
/// use qsec::QsecPlatform;
///
/// let mut p = QsecPlatform::new().unwrap();
///
/// // Emite token PQC-JWT
/// let token = p.jwt_issue("user@example.com", Default::default(), 3600, "api.example.com").unwrap();
///
/// // Verifica
/// let claims = p.jwt_verify(&token, "api.example.com").unwrap();
/// println!("Subject: {}", claims.sub);
/// ```
pub struct QsecPlatform {
    /// Motor PQC híbrido
    pub engine:       PqcEngine,
    /// Registro de chaves
    pub key_registry: KeyRegistry,
    /// Scanner de crypto fraca
    pub scanner:      CryptoScanner,
    /// Gerenciador de API keys
    pub api_keys:     ApiKeyManager,
    /// Gerador de SBOM
    pub sbom_gen:     SbomGenerator,
    /// ID do builder (para attestations)
    pub builder_id:   String,
}

impl QsecPlatform {
    /// Cria a plataforma com configuração padrão.
    pub fn new() -> QsecResult<Self> {
        Self::with_builder_id("qsec-platform")
    }

    /// Cria a plataforma com builder ID customizado.
    pub fn with_builder_id(builder_id: impl Into<String>) -> QsecResult<Self> {
        let engine       = PqcEngine::new();
        let key_registry = KeyRegistry::new(PqcEngine::new())
            .map_err(QsecError::ZeroTrust)?;

        println!(
            "[QSEC v{VERSION}] Backend: {}",
            engine.backend_name()
        );

        Ok(Self {
            engine,
            key_registry,
            scanner:    CryptoScanner::new(),
            api_keys:   ApiKeyManager::new(),
            sbom_gen:   SbomGenerator::new(),
            builder_id: builder_id.into(),
        })
    }

    // ── Scan ─────────────────────────────────────────────────────────────────

    /// Escaneia um arquivo ou diretório em busca de crypto fraca.
    pub fn scan(&mut self, path: &Path) -> QsecResult<&[CryptoFinding]> {
        self.scanner.clear();
        if path.is_file() {
            self.scanner.scan_file(path)?;
        } else {
            self.scanner.scan_directory(path)?;
        }
        Ok(&self.scanner.findings)
    }

    /// Relatório de scan em texto legível.
    pub fn scan_report_text(&self) -> String {
        self.scanner.report_text()
    }

    /// Relatório de scan em JSON.
    pub fn scan_report_json(&self) -> QsecResult<String> {
        self.scanner.report_json().map_err(QsecError::Serde)
    }

    // ── PQC Engine ───────────────────────────────────────────────────────────

    /// Informações do motor PQC.
    pub fn engine_info(&self) -> EngineInfo {
        self.engine.info()
    }

    // ── JWT ──────────────────────────────────────────────────────────────────

    /// Emite um PQC-JWT.
    pub fn jwt_issue(
        &self,
        subject:   &str,
        extra:     HashMap<String, serde_json::Value>,
        ttl_secs:  i64,
        audience:  &str,
    ) -> QsecResult<String> {
        let mgr = PqcJwtManager::new(&self.engine, &self.key_registry);
        mgr.issue(subject, extra, ttl_secs, audience, "qsec-platform")
            .map_err(QsecError::ZeroTrust)
    }

    /// Verifica um PQC-JWT.
    pub fn jwt_verify(&self, token: &str, audience: &str) -> QsecResult<JwtClaims> {
        let mgr = PqcJwtManager::new(&self.engine, &self.key_registry);
        mgr.verify(token, audience, None)
            .map_err(QsecError::ZeroTrust)
    }

    // ── API Keys ─────────────────────────────────────────────────────────────

    /// Cria uma API key.
    pub fn api_key_create(
        &mut self,
        name:     &str,
        scopes:   Vec<String>,
        ttl_days: Option<u32>,
    ) -> QsecResult<(String, String)> {
        self.api_keys.create(name, scopes, ttl_days)
            .map_err(QsecError::ZeroTrust)
    }

    /// Verifica uma API key.
    pub fn api_key_verify(
        &mut self,
        raw_key:       &str,
        required_scope: Option<&str>,
    ) -> QsecResult<String> {
        self.api_keys.verify(raw_key, required_scope)
            .map(|e| e.key_id.clone())
            .map_err(QsecError::ZeroTrust)
    }

    // ── Supply Chain ─────────────────────────────────────────────────────────

    /// Gera SBOM CycloneDX 1.5 de um projeto.
    pub fn generate_sbom(&self, project_path: &Path) -> QsecResult<Sbom> {
        self.sbom_gen.generate_from_project(project_path)
            .map_err(QsecError::SupplyChain)
    }

    // ── Pipeline Completo ────────────────────────────────────────────────────

    /// Executa o pipeline de segurança completo em 4 etapas.
    pub fn full_pipeline(
        &mut self,
        project_path: &Path,
        artifacts:    &[&Path],
        output_dir:   &Path,
        source_repo:  Option<&str>,
    ) -> QsecResult<PipelineReport> {
        std::fs::create_dir_all(output_dir)?;
        let mut report = PipelineReport::default();

        // Etapa 1 — Scan
        println!("[1/4] Scanning for weak cryptography...");
        let findings = self.scan(project_path)?.to_vec();
        let counts   = self.scanner.count_by_severity();
        let scan_out = output_dir.join("crypto_scan_report.json");
        std::fs::write(&scan_out, self.scan_report_json()?)?;
        println!("  → {} findings ({} CRITICAL, {} HIGH)",
                 findings.len(), counts.critical, counts.high);
        report.scan_findings      = findings.len();
        report.scan_critical      = counts.critical;
        report.scan_report_path   = scan_out;

        // Etapa 2 — SBOM
        println!("[2/4] Generating SBOM (CycloneDX 1.5)...");
        let sbom      = self.generate_sbom(project_path)?;
        let sbom_path = output_dir.join("sbom.cyclonedx.json");
        std::fs::write(&sbom_path, sbom.to_json().map_err(QsecError::SupplyChain)?)?;
        println!("  → {} components | {:?}", sbom.components.len(), sbom_path);
        report.sbom_components = sbom.components.len();
        report.sbom_path       = sbom_path;

        // Etapa 3 — Assinatura
        println!("[3/4] Signing {} artifact(s)...", artifacts.len());
        let sign_kp     = self.key_registry.active_signing_key()
            .map_err(QsecError::ZeroTrust)?;
        let signer      = ArtifactSigner::new(&self.engine, sign_kp);
        let manifest_out = output_dir.join("artifact_manifest.json");
        let mut build_info = HashMap::new();
        build_info.insert("project".to_string(), project_path.display().to_string());
        build_info.insert("qsec_version".to_string(), VERSION.to_string());

        let mut signed_count = 0usize;
        for art in artifacts {
            match signer.sign(art, Some(build_info.clone())) {
                Ok(_)  => { signed_count += 1; println!("  ✅ {}", art.display()); }
                Err(e) => println!("  ❌ {}: {e}", art.display()),
            }
        }
        println!("  → {signed_count}/{} signed", artifacts.len());
        report.artifacts_signed = signed_count;
        report.manifest_path    = manifest_out;

        // Etapa 4 — Attestation
        println!("[4/4] Creating build attestation...");
        let att_builder = AttestationBuilder::new(&self.engine, sign_kp, &self.builder_id);
        let att = att_builder
            .attest(artifacts, source_repo, None, None)
            .map_err(QsecError::SupplyChain)?;
        att_builder.verify(&att).map_err(QsecError::SupplyChain)?;
        let att_path = output_dir.join("attestation.json");
        std::fs::write(
            &att_path,
            att.to_envelope().map_err(QsecError::SupplyChain)?,
        )?;
        println!("  ✅ Attestation valid | {:?}", att_path);
        report.attestation_subjects = att.subject.len();
        report.attestation_path     = att_path;

        println!("\n[QSEC] Pipeline complete → {:?}", output_dir);
        Ok(report)
    }
}

/// Resultado do pipeline completo.
#[derive(Debug, Default)]
pub struct PipelineReport {
    pub scan_findings:       usize,
    pub scan_critical:       usize,
    pub scan_report_path:    PathBuf,
    pub sbom_components:     usize,
    pub sbom_path:           PathBuf,
    pub artifacts_signed:    usize,
    pub manifest_path:       PathBuf,
    pub attestation_subjects: usize,
    pub attestation_path:    PathBuf,
}
