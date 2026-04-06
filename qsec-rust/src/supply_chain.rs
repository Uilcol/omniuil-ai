//! # Supply Chain Protection — Pilar 3
//!
//! Proteção completa da cadeia de suprimentos:
//!
//! - **SBOM** (CycloneDX JSON 1.5) com fingerprint SHA3-256
//! - **ArtifactSigner**: assina e verifica artefatos com PQC híbrido
//! - **BuildAttestation**: attestation verificável estilo SLSA Level 2+
//! - **Detecção de adulteração**: SHA3-256 + assinatura híbrida

use std::{
    collections::HashMap,
    path::Path,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    error::{SupplyChainError, SupplyChainResult},
    pqc_engine::{HybridDsaKeyPair, HybridSignature, PqcEngine},
};

// ─── SBOM ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(rename = "bom-ref")]
    pub bom_ref:     String,
    #[serde(rename = "type")]
    pub kind:        String,
    pub name:        String,
    pub version:     String,
    pub purl:        String,
    pub hashes:      Vec<SbomHash>,
    pub licenses:    Vec<SbomLicense>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomHash {
    pub alg:     String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomLicense {
    pub license: SbomLicenseId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomLicenseId {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    #[serde(rename = "bomFormat")]
    pub bom_format:    String,
    #[serde(rename = "specVersion")]
    pub spec_version:  String,
    pub version:       u32,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub metadata:      SbomMetadata,
    pub components:    Vec<SbomComponent>,
    pub dependencies:  Vec<SbomDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    pub timestamp:  String,
    pub tools:      Vec<SbomTool>,
    pub component:  SbomMetaComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomTool {
    pub vendor:  String,
    pub name:    String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetaComponent {
    #[serde(rename = "type")]
    pub kind:    String,
    pub name:    String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    #[serde(rename = "ref")]
    pub dep_ref:  String,
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

impl Sbom {
    pub fn to_json(&self) -> SupplyChainResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SupplyChainError::SbomGeneration(e.to_string()))
    }
}

/// Gerador de SBOM CycloneDX 1.5.
pub struct SbomGenerator;

impl SbomGenerator {
    pub fn new() -> Self { Self }

    /// Gera SBOM a partir de um diretório de projeto.
    pub fn generate_from_project(&self, project_path: &Path) -> SupplyChainResult<Sbom> {
        let name    = project_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let version = self.detect_version(project_path);

        let mut components = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Detecta de Cargo.toml
        let cargo_path = project_path.join("Cargo.toml");
        if cargo_path.exists() {
            for comp in self.from_cargo_toml(&cargo_path)? {
                let key = format!("{}@{}", comp.name, comp.version);
                if seen.insert(key) { components.push(comp); }
            }
        }

        // Detecta de Cargo.lock (mais preciso)
        let lock_path = project_path.join("Cargo.lock");
        if lock_path.exists() {
            for comp in self.from_cargo_lock(&lock_path)? {
                let key = format!("{}@{}", comp.name, comp.version);
                if seen.insert(key) { components.push(comp); }
            }
        }

        Ok(Sbom {
            bom_format:    "CycloneDX".to_string(),
            spec_version:  "1.5".to_string(),
            version:       1,
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            metadata: SbomMetadata {
                timestamp: Utc::now().to_rfc3339(),
                tools: vec![SbomTool {
                    vendor:  "QSEC".to_string(),
                    name:    "qsec".to_string(),
                    version: "3.0.0".to_string(),
                }],
                component: SbomMetaComponent {
                    kind:    "application".to_string(),
                    name:    name.to_string(),
                    version: version.clone(),
                },
            },
            components,
            dependencies: Vec::new(),
        })
    }

    fn detect_version(&self, path: &Path) -> String {
        let cargo = path.join("Cargo.toml");
        if let Ok(content) = std::fs::read_to_string(&cargo) {
            for line in content.lines() {
                if line.trim().starts_with("version") {
                    if let Some(v) = line.split('=').nth(1) {
                        return v.trim().trim_matches('"').to_string();
                    }
                }
            }
        }
        "0.0.0".to_string()
    }

    fn from_cargo_toml(&self, path: &Path) -> SupplyChainResult<Vec<SbomComponent>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SupplyChainError::SbomGeneration(e.to_string()))?;
        let mut components = Vec::new();

        let mut in_deps = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("[dependencies]")
                || trimmed.starts_with("[dev-dependencies]")
            {
                in_deps = true;
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_deps = false;
                continue;
            }
            if !in_deps { continue; }

            if let Some(pos) = trimmed.find(" = ") {
                let name = trimmed[..pos].trim().trim_matches('"');
                let val  = trimmed[pos+3..].trim().trim_matches('"');
                // Pega versão simples (ignora tabelas { version = ... })
                let version = if val.starts_with('{') {
                    val.split('"')
                        .nth(1)
                        .unwrap_or("unknown")
                } else {
                    val.trim_matches('"')
                };
                let purl = format!("pkg:cargo/{name}@{version}");
                components.push(SbomComponent {
                    bom_ref:     purl.clone(),
                    kind:        "library".to_string(),
                    name:        name.to_string(),
                    version:     version.to_string(),
                    purl,
                    hashes:      Vec::new(),
                    licenses:    Vec::new(),
                    description: String::new(),
                });
            }
        }
        Ok(components)
    }

    fn from_cargo_lock(&self, path: &Path) -> SupplyChainResult<Vec<SbomComponent>> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SupplyChainError::SbomGeneration(e.to_string()))?;
        let mut components = Vec::new();
        let mut current_name    = String::new();
        let mut current_version = String::new();
        let mut current_checksum = String::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                // Salva o componente anterior
                if !current_name.is_empty() && !current_version.is_empty() {
                    let purl = format!("pkg:cargo/{current_name}@{current_version}");
                    let mut hashes = Vec::new();
                    if !current_checksum.is_empty() {
                        hashes.push(SbomHash {
                            alg:     "SHA-256".to_string(),
                            content: current_checksum.clone(),
                        });
                    }
                    components.push(SbomComponent {
                        bom_ref:     purl.clone(),
                        kind:        "library".to_string(),
                        name:        current_name.clone(),
                        version:     current_version.clone(),
                        purl,
                        hashes,
                        licenses:    Vec::new(),
                        description: String::new(),
                    });
                }
                current_name.clear();
                current_version.clear();
                current_checksum.clear();
                continue;
            }
            if let Some(v) = trimmed.strip_prefix("name = ") {
                current_name = v.trim_matches('"').to_string();
            } else if let Some(v) = trimmed.strip_prefix("version = ") {
                current_version = v.trim_matches('"').to_string();
            } else if let Some(v) = trimmed.strip_prefix("checksum = ") {
                current_checksum = v.trim_matches('"').to_string();
            }
        }

        Ok(components)
    }
}

impl Default for SbomGenerator {
    fn default() -> Self { Self::new() }
}

// ─── ARTIFACT SIGNER ──────────────────────────────────────────────────────────

/// Artefato assinado com PQC híbrido.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedArtifact {
    pub path:       String,
    pub sha3_256:   String,
    pub sha2_256:   String,
    pub size_bytes: u64,
    pub signature:  HybridSignature,
    pub key_id:     String,
    pub algorithm:  String,
    pub signed_at:  String,
    pub build_info: HashMap<String, String>,
}

/// Assina e verifica artefatos com criptografia PQC híbrida.
pub struct ArtifactSigner<'a> {
    engine:  &'a PqcEngine,
    keypair: &'a HybridDsaKeyPair,
}

impl<'a> ArtifactSigner<'a> {
    pub fn new(engine: &'a PqcEngine, keypair: &'a HybridDsaKeyPair) -> Self {
        Self { engine, keypair }
    }

    /// Assina um artefato. Lê o arquivo, computa hashes e assina com PQC híbrido.
    pub fn sign(
        &self,
        artifact_path: &Path,
        build_info: Option<HashMap<String, String>>,
    ) -> SupplyChainResult<SignedArtifact> {
        if !artifact_path.exists() {
            return Err(SupplyChainError::ArtifactNotFound(
                artifact_path.display().to_string()
            ));
        }

        let data = std::fs::read(artifact_path)
            .map_err(|e| SupplyChainError::ArtifactNotFound(e.to_string()))?;

        let sha3 = hex::encode(<Sha3_256 as Digest>::digest(&data));
        let sha2 = hex::encode(sha2::Sha256::digest(&data));

        let sig = self.engine
            .hybrid_sign(&data, self.keypair)
            .map_err(|_e| SupplyChainError::SignatureVerification {
                artifact: artifact_path.display().to_string(),
            })?;

        Ok(SignedArtifact {
            path:       artifact_path.display().to_string(),
            sha3_256:   sha3,
            sha2_256:   sha2,
            size_bytes: data.len() as u64,
            signature:  sig,
            key_id:     self.keypair.key_id.clone(),
            algorithm:  self.keypair.algorithm.clone(),
            signed_at:  Utc::now().to_rfc3339(),
            build_info: build_info.unwrap_or_default(),
        })
    }

    /// Verifica integridade e assinatura de um artefato.
    ///
    /// Verifica em ordem:
    /// 1. Arquivo existe
    /// 2. Tamanho correto
    /// 3. SHA3-256 em tempo constante (evita timing oracle)
    /// 4. Assinatura PQC híbrida
    pub fn verify(
        &self,
        artifact_path: &Path,
        signed: &SignedArtifact,
    ) -> SupplyChainResult<()> {
        if !artifact_path.exists() {
            return Err(SupplyChainError::ArtifactNotFound(
                artifact_path.display().to_string()
            ));
        }

        let data = std::fs::read(artifact_path)
            .map_err(|e| SupplyChainError::ArtifactNotFound(e.to_string()))?;

        // Tamanho
        if data.len() as u64 != signed.size_bytes {
            return Err(SupplyChainError::SizeMismatch {
                artifact: artifact_path.display().to_string(),
                expected: signed.size_bytes,
                actual:   data.len() as u64,
            });
        }

        // SHA3-256 — comparação em tempo constante
        let actual_hash = hex::encode(<Sha3_256 as Digest>::digest(&data));
        let hashes_match: bool = actual_hash.as_bytes()
            .ct_eq(signed.sha3_256.as_bytes())
            .into();

        if !hashes_match {
            return Err(SupplyChainError::HashMismatch {
                artifact: artifact_path.display().to_string(),
                expected: signed.sha3_256.clone(),
                actual:   actual_hash,
            });
        }

        // Assinatura híbrida
        let ok = self.engine
            .hybrid_verify(&data, &signed.signature, &self.keypair.public_key)
            .map_err(|_| SupplyChainError::SignatureVerification {
                artifact: artifact_path.display().to_string(),
            })?;

        if !ok {
            return Err(SupplyChainError::SignatureVerification {
                artifact: artifact_path.display().to_string(),
            });
        }

        Ok(())
    }

    /// Assina todos os artefatos de um diretório e gera manifest JSON.
    pub fn sign_directory(
        &self,
        dir: &Path,
        manifest_path: &Path,
        build_info: Option<HashMap<String, String>>,
    ) -> SupplyChainResult<ArtifactManifest> {
        let mut signed = Vec::new();
        let mut errors = Vec::new();

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && !path.extension().map(|e| e == "json").unwrap_or(false)
                {
                    match self.sign(&path, build_info.clone()) {
                        Ok(sa)  => signed.push(sa),
                        Err(e)  => errors.push(format!("{}: {e}", path.display())),
                    }
                }
            }
        }

        let manifest = ArtifactManifest {
            version:        "3.0".to_string(),
            generator:      "qsec".to_string(),
            generated_at:   Utc::now().to_rfc3339(),
            key_id:         self.keypair.key_id.clone(),
            algorithm:      self.keypair.algorithm.clone(),
            artifact_count: signed.len(),
            artifacts:      signed,
            errors,
        };

        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| SupplyChainError::ManifestWrite(e.to_string()))?;
        std::fs::write(manifest_path, json)
            .map_err(|e| SupplyChainError::ManifestWrite(e.to_string()))?;

        Ok(manifest)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub version:        String,
    pub generator:      String,
    pub generated_at:   String,
    pub key_id:         String,
    pub algorithm:      String,
    pub artifact_count: usize,
    pub artifacts:      Vec<SignedArtifact>,
    pub errors:         Vec<String>,
}

// ─── BUILD ATTESTATION ────────────────────────────────────────────────────────

/// Attestation verificável de build (SLSA Level 2+).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAttestation {
    pub subject:    Vec<AttestationSubject>,
    pub builder_id: String,
    pub build_type: String,
    pub invocation: AttestationInvocation,
    pub materials:  Vec<AttestationMaterial>,
    pub metadata:   AttestationMetadata,
    /// Assinatura PQC do payload canônico
    pub signature:  Option<HybridSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSubject {
    pub name:   String,
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInvocation {
    pub config_source: AttestationConfigSource,
    pub parameters:    HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfigSource {
    pub uri:    String,
    /// Rastreabilidade — não segurança criptográfica
    pub commit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMaterial {
    pub uri:    String,
    pub commit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMetadata {
    pub build_started_on: String,
    pub completeness:     AttestationCompleteness,
    pub reproducible:     bool,
    pub key_id:           String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationCompleteness {
    pub parameters:  bool,
    pub environment: bool,
    pub materials:   bool,
}

impl BuildAttestation {
    /// Payload canônico para assinatura (sort_keys para determinismo).
    pub fn canonical_payload(&self) -> SupplyChainResult<Vec<u8>> {
        // Cria versão sem signature para o payload
        let unsigned = serde_json::json!({
            "subject":    self.subject,
            "builderId":  self.builder_id,
            "buildType":  self.build_type,
            "invocation": self.invocation,
            "materials":  self.materials,
            "metadata":   self.metadata,
        });
        serde_json::to_vec(&unsigned)
            .map_err(|e| SupplyChainError::AttestationVerification(e.to_string()))
    }

    /// Envelope DSSE-style para distribuição.
    pub fn to_envelope(&self) -> SupplyChainResult<String> {
        let payload = self.canonical_payload()?;
        let envelope = serde_json::json!({
            "payloadType": "application/vnd.qsec.attestation.v3+json",
            "payload":     serde_json::Value::String(
                String::from_utf8_lossy(&payload).to_string()
            ),
            "signatures": [{
                "sig": self.signature.as_ref().map(|s| &s.classical_sig),
                "keyid": self.metadata.key_id,
            }],
        });
        serde_json::to_string_pretty(&envelope)
            .map_err(|e| SupplyChainError::AttestationVerification(e.to_string()))
    }
}

/// Constrói e verifica attestations de build.
pub struct AttestationBuilder<'a> {
    engine:     &'a PqcEngine,
    keypair:    &'a HybridDsaKeyPair,
    builder_id: String,
}

impl<'a> AttestationBuilder<'a> {
    pub fn new(
        engine:     &'a PqcEngine,
        keypair:    &'a HybridDsaKeyPair,
        builder_id: impl Into<String>,
    ) -> Self {
        Self { engine, keypair, builder_id: builder_id.into() }
    }

    /// Cria e assina uma attestation de build.
    pub fn attest(
        &self,
        artifacts:      &[&Path],
        source_repo:    Option<&str>,
        source_commit:  Option<&str>,
        build_command:  Option<&[&str]>,
    ) -> SupplyChainResult<BuildAttestation> {
        // Constrói subjects com hashes
        let mut subject = Vec::new();
        for path in artifacts {
            if path.exists() {
                let data = std::fs::read(path)
                    .map_err(|e| SupplyChainError::ArtifactNotFound(e.to_string()))?;
                let mut digest = HashMap::new();
                digest.insert("sha3-256".to_string(), hex::encode(<Sha3_256 as Digest>::digest(&data)));
                digest.insert("sha2-256".to_string(), hex::encode(sha2::Sha256::digest(&data)));
                subject.push(AttestationSubject {
                    name: path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    digest,
                });
            }
        }

        // Detecta contexto Git
        let git_commit = source_commit
            .map(str::to_string)
            .or_else(|| detect_git_commit())
            .unwrap_or_default();
        let git_repo = source_repo
            .map(str::to_string)
            .or_else(|| detect_git_remote())
            .unwrap_or_default();

        let mut att = BuildAttestation {
            subject,
            builder_id: self.builder_id.clone(),
            build_type: "https://qsec.io/buildType/v3".to_string(),
            invocation: AttestationInvocation {
                config_source: AttestationConfigSource {
                    uri:    git_repo.clone(),
                    commit: git_commit.clone(),
                },
                parameters: build_command
                    .map(|cmd| {
                        let mut m = HashMap::new();
                        m.insert("command".to_string(), cmd.join(" "));
                        m
                    })
                    .unwrap_or_default(),
            },
            materials: if !git_repo.is_empty() {
                vec![AttestationMaterial { uri: git_repo, commit: git_commit }]
            } else {
                Vec::new()
            },
            metadata: AttestationMetadata {
                build_started_on: Utc::now().to_rfc3339(),
                completeness: AttestationCompleteness {
                    parameters:  true,
                    environment: false,
                    materials:   !att_materials_empty(&source_repo),
                },
                reproducible: false,
                key_id: self.keypair.key_id.clone(),
            },
            signature: None,
        };

        // Assina o payload canônico
        let payload = att.canonical_payload()?;
        let sig = self.engine
            .hybrid_sign(&payload, self.keypair)
            .map_err(|e| SupplyChainError::AttestationVerification(e.to_string()))?;
        att.signature = Some(sig);

        Ok(att)
    }

    /// Verifica uma attestation.
    pub fn verify(&self, att: &BuildAttestation) -> SupplyChainResult<()> {
        let sig = att.signature.as_ref()
            .ok_or(SupplyChainError::UnsignedAttestation)?;

        let payload = att.canonical_payload()?;

        let ok = self.engine
            .hybrid_verify(&payload, sig, &self.keypair.public_key)
            .map_err(|e| SupplyChainError::AttestationVerification(e.to_string()))?;

        if !ok {
            return Err(SupplyChainError::AttestationVerification(
                "hybrid signature verification failed".to_string()
            ));
        }

        Ok(())
    }
}

fn att_materials_empty(source_repo: &Option<&str>) -> bool {
    source_repo.map(str::is_empty).unwrap_or(true)
}

// ─── Git helpers ──────────────────────────────────────────────────────────────

fn detect_git_commit() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let commit = String::from_utf8(out.stdout).ok()?.trim().to_string();
    // Valida formato SHA-1/SHA-256 do git
    if commit.len() >= 40 && commit.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(commit)
    } else {
        None
    }
}

fn detect_git_remote() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let remote = String::from_utf8(out.stdout).ok()?.trim().to_string();
    // Valida formato URL
    if remote.starts_with("https://")
        || remote.starts_with("git@")
        || remote.starts_with("ssh://")
    {
        Some(remote)
    } else {
        None
    }
}
