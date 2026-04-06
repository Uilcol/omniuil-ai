//! Suite de testes de integração do QSEC v3.
//!
//! Cobre os 4 pilares com casos reais:
//!   - Scanner: 14 regras de detecção
//!   - PQC Engine: KEM, DSA, serialização, zeroização
//!   - Supply Chain: SBOM, signing, attestation, tamper detection
//!   - Zero Trust: JWT (emissão, verificação, revogação, rejeições), KeyRegistry, APIKeys
//!
//! Execute: cargo test -- --test-output immediate

use std::{collections::HashMap, path::PathBuf};
use tempfile::TempDir;

use qsec::{
    error::{ZeroTrustError, SupplyChainError},
    pqc_engine::PqcEngine,
    scanner::{CryptoScanner, Severity},
    supply_chain::{ArtifactSigner, AttestationBuilder, SbomGenerator},
    zero_trust::{ApiKeyManager, KeyRegistry, PqcJwtManager},
};

// ════════════════════════════════════════════════════════════════════════════
// PILAR 1 — CRYPTO SCANNER
// ════════════════════════════════════════════════════════════════════════════

fn scan_code(code: &str) -> Vec<qsec::CryptoFinding> {
    use std::io::Write;
    let mut f   = tempfile::NamedTempFile::with_suffix(".rs").unwrap();
    write!(f, "{code}").unwrap();
    let mut scanner = CryptoScanner::new();
    scanner.scan_file(f.path()).unwrap();
    scanner.findings
}

#[test]
fn scanner_detects_rsa() {
    let findings = scan_code(r#"use rsa::RsaPrivateKey; let k = RSA::generate(2048);"#);
    assert!(findings.iter().any(|f| f.rule_id == "QSC-001"),
            "Should detect RSA");
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
}

#[test]
fn scanner_detects_ecdsa() {
    let findings = scan_code("use p256::ecdsa::ECDSA; let k = ECDH::new(secp256k1);");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-002"));
}

#[test]
fn scanner_detects_md5() {
    let findings = scan_code("use md5; let h = Md5::new().chain(data).finalize();");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-010"));
    assert!(findings.iter().any(|f| f.severity == Severity::High));
}

#[test]
fn scanner_detects_sha1() {
    let findings = scan_code("use sha1::Sha1; let h = Sha1::new();");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-011"));
}

#[test]
fn scanner_detects_aes_ecb() {
    let findings = scan_code("let cipher = Ecb::<Aes256, NoPadding>::new(key);");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-012"));
}

#[test]
fn scanner_detects_des() {
    let findings = scan_code("use des::Des; let c = Des::new(&key);");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-013"));
}

#[test]
fn scanner_detects_rc4() {
    let findings = scan_code("use rc4::Rc4; let c = Rc4::new(&key);");
    assert!(findings.iter().any(|f| f.rule_id == "QSC-014"));
}

#[test]
fn scanner_detects_jwt_none() {
    let findings = scan_code(r#"let token = encode(claims, key, algorithm: "none");"#);
    assert!(findings.iter().any(|f| f.rule_id == "QSC-020"));
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
}

#[test]
fn scanner_detects_jwt_hs256() {
    let findings = scan_code(r#"let token = encode(claims, key, algorithm: "HS256");"#);
    assert!(findings.iter().any(|f| f.rule_id == "QSC-021"));
}

#[test]
fn scanner_detects_jwt_rs256() {
    let findings = scan_code(r#"let alg = Algorithm::RS256;"#);
    assert!(findings.iter().any(|f| f.rule_id == "QSC-022"));
}

#[test]
fn scanner_detects_hardcoded_key() {
    let findings = scan_code(r#"let api_key = "supersecret_production_key_12345678";"#);
    assert!(findings.iter().any(|f| f.rule_id == "QSC-030"));
}

#[test]
fn scanner_ignores_comments() {
    // Comentários não devem gerar findings
    let findings = scan_code("// RSA is quantum-vulnerable — use ML-KEM instead\n// MD5 is broken");
    let code_findings: Vec<_> = findings.iter()
        .filter(|f| f.code_snippet.starts_with("//"))
        .collect();
    assert!(code_findings.is_empty(), "Comments must not generate findings");
}

#[test]
fn scanner_json_report_is_valid() {
    let mut scanner = CryptoScanner::new();
    let mut f = tempfile::NamedTempFile::with_suffix(".rs").unwrap();
    use std::io::Write;
    write!(f, "use rsa::RSA; Md5::new(); RC4::new();").unwrap();
    scanner.scan_file(f.path()).unwrap();

    let json = scanner.report_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.is_array());
    assert!(parsed.as_array().unwrap().len() >= 2);
}

#[test]
fn scanner_counts_severity() {
    let mut scanner = CryptoScanner::new();
    let mut f = tempfile::NamedTempFile::with_suffix(".rs").unwrap();
    use std::io::Write;
    write!(f, r#"RSA::generate(); Md5::new(); algorithm: "none";"#).unwrap();
    scanner.scan_file(f.path()).unwrap();

    let counts = scanner.count_by_severity();
    assert!(counts.critical >= 1, "Should have CRITICAL findings");
}

#[test]
fn scanner_empty_file_no_crash() {
    let mut scanner = CryptoScanner::new();
    let f = tempfile::NamedTempFile::with_suffix(".rs").unwrap();
    let result = scanner.scan_file(f.path());
    assert!(result.is_ok());
    assert!(scanner.findings.is_empty());
}

// ════════════════════════════════════════════════════════════════════════════
// PILAR 2 — PQC ENGINE
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn pqc_engine_kem_keypair_generation() {
    let engine = PqcEngine::new();
    let kp = engine.generate_kem_keypair().unwrap();

    assert!(!kp.key_id.is_empty());
    assert_eq!(kp.public_key.classical_public.len(), 32); // X25519 = 32 bytes
    assert!(kp.algorithm.starts_with("X25519"));
}

#[test]
fn pqc_engine_dsa_keypair_generation() {
    let engine = PqcEngine::new();
    let kp = engine.generate_dsa_keypair().unwrap();

    assert!(!kp.key_id.is_empty());
    assert_eq!(kp.public_key.classical_public.len(), 32); // Ed25519 = 32 bytes
    assert!(kp.algorithm.starts_with("Ed25519"));
}

#[test]
fn pqc_engine_keypair_debug_redacts_private_key() {
    let engine  = PqcEngine::new();
    let kem_kp  = engine.generate_kem_keypair().unwrap();
    let dsa_kp  = engine.generate_dsa_keypair().unwrap();
    let kem_str = format!("{kem_kp:?}");
    let dsa_str = format!("{dsa_kp:?}");

    assert!(kem_str.contains("REDACTED"), "KEM debug must redact private key");
    assert!(dsa_str.contains("REDACTED"), "DSA debug must redact private key");
    // Garante que o hex da chave privada não aparece
    assert!(!kem_str.contains(&hex::encode(&kem_kp.private_key.pqc)));
}

#[test]
fn pqc_engine_encrypt_decrypt_roundtrip() {
    let engine    = PqcEngine::new();
    let kp        = engine.generate_kem_keypair().unwrap();
    let plaintext = b"Hello, post-quantum world! Dados secretos de producao.";

    let ct        = engine.hybrid_encrypt(plaintext, &kp.public_key, None).unwrap();
    let decrypted = engine.hybrid_decrypt(&ct, &kp, None).unwrap();

    assert_eq!(plaintext.as_ref(), decrypted.as_slice());
}

#[test]
fn pqc_engine_encrypt_with_aad() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_kem_keypair().unwrap();
    let data    = b"authenticated payload";
    let aad     = b"authenticated header v3";

    let ct   = engine.hybrid_encrypt(data, &kp.public_key, Some(aad)).unwrap();
    let dec  = engine.hybrid_decrypt(&ct, &kp, Some(aad)).unwrap();
    assert_eq!(data.as_ref(), dec.as_slice());
}

#[test]
fn pqc_engine_wrong_aad_fails_decryption() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_kem_keypair().unwrap();
    let data   = b"secret";

    let ct = engine.hybrid_encrypt(data, &kp.public_key, Some(b"correct aad")).unwrap();
    let result = engine.hybrid_decrypt(&ct, &kp, Some(b"wrong aad"));
    assert!(result.is_err(), "Wrong AAD must fail decryption");
}

#[test]
fn pqc_engine_wrong_key_fails_decryption() {
    let engine = PqcEngine::new();
    let kp1    = engine.generate_kem_keypair().unwrap();
    let kp2    = engine.generate_kem_keypair().unwrap();
    let data   = b"secret for kp1";

    let ct     = engine.hybrid_encrypt(data, &kp1.public_key, None).unwrap();
    let result = engine.hybrid_decrypt(&ct, &kp2, None);
    assert!(result.is_err(), "Wrong key must fail decryption");
}

#[test]
fn pqc_engine_sign_verify() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let message = b"Software artifact v3.0.0 — production build";

    let sig = engine.hybrid_sign(message, &kp).unwrap();
    let ok  = engine.hybrid_verify(message, &sig, &kp.public_key).unwrap();
    assert!(ok, "Valid signature must verify");
}

#[test]
fn pqc_engine_tampered_message_rejected() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let message = b"original message";

    let sig     = engine.hybrid_sign(message, &kp).unwrap();
    let tampered = b"TAMPERED message";
    let ok       = engine.hybrid_verify(tampered, &sig, &kp.public_key).unwrap();
    assert!(!ok, "Tampered message must fail verification");
}

#[test]
fn pqc_engine_different_keys_fail_verify() {
    let engine = PqcEngine::new();
    let kp1    = engine.generate_dsa_keypair().unwrap();
    let kp2    = engine.generate_dsa_keypair().unwrap();

    let sig = engine.hybrid_sign(b"message", &kp1).unwrap();
    let ok  = engine.hybrid_verify(b"message", &sig, &kp2.public_key).unwrap();
    assert!(!ok, "Wrong key must fail verification");
}

#[test]
fn pqc_engine_ciphertext_serialization_roundtrip() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_kem_keypair().unwrap();
    let data   = b"serialization test payload";

    let ct  = engine.hybrid_encrypt(data, &kp.public_key, None).unwrap();
    let raw = ct.serialize().unwrap();
    let ct2 = qsec::HybridCiphertext::deserialize(&raw).unwrap();

    // Decripta com o CT deserializado
    let dec = engine.hybrid_decrypt(&ct2, &kp, None).unwrap();
    assert_eq!(data.as_ref(), dec.as_slice());
}

#[test]
fn pqc_engine_signature_serialization_roundtrip() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let message = b"sig serialization test";

    let sig  = engine.hybrid_sign(message, &kp).unwrap();
    let raw  = sig.serialize().unwrap();
    let sig2 = qsec::HybridSignature::deserialize(&raw).unwrap();

    let ok = engine.hybrid_verify(message, &sig2, &kp.public_key).unwrap();
    assert!(ok, "Deserialized signature must verify");
}

#[test]
fn pqc_engine_large_payload() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_kem_keypair().unwrap();
    let data   = vec![0xABu8; 1_000_000]; // 1 MB

    let ct  = engine.hybrid_encrypt(&data, &kp.public_key, None).unwrap();
    let dec = engine.hybrid_decrypt(&ct, &kp, None).unwrap();
    assert_eq!(data, dec);
}

#[test]
fn pqc_engine_info_has_hndl_protection() {
    let engine = PqcEngine::new();
    let info   = engine.info();
    assert!(info.harvest_now_decrypt_later_protection);
    assert_eq!(info.symmetric, "AES-256-GCM");
    assert_eq!(info.kdf, "HKDF-SHA3-256");
}

// ════════════════════════════════════════════════════════════════════════════
// PILAR 3 — SUPPLY CHAIN
// ════════════════════════════════════════════════════════════════════════════

fn make_temp_artifact(content: &[u8]) -> (TempDir, std::path::PathBuf) {
    let dir  = TempDir::new().unwrap();
    let path = dir.path().join("artifact.bin");
    std::fs::write(&path, content).unwrap();
    (dir, path)
}

#[test]
fn supply_chain_sbom_generation() {
    let dir  = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nserde = \"1\"\ncryptography = \"42\"\n"
    ).unwrap();

    let gen  = SbomGenerator::new();
    let sbom = gen.generate_from_project(dir.path()).unwrap();

    assert_eq!(sbom.bom_format, "CycloneDX");
    assert_eq!(sbom.spec_version, "1.5");
    assert!(sbom.serial_number.starts_with("urn:uuid:"));
    assert!(!sbom.components.is_empty());
}

#[test]
fn supply_chain_sbom_json_valid() {
    let dir  = TempDir::new().unwrap();
    let gen  = SbomGenerator::new();
    let sbom = gen.generate_from_project(dir.path()).unwrap();
    let json = sbom.to_json().unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["bomFormat"], "CycloneDX");
    assert!(parsed["components"].is_array());
}

#[test]
fn supply_chain_sign_and_verify() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_dsa_keypair().unwrap();
    let signer = ArtifactSigner::new(&engine, &kp);
    let (_dir, path) = make_temp_artifact(b"production binary v3.0.0");

    let sa = signer.sign(&path, None).unwrap();
    assert!(!sa.sha3_256.is_empty());
    assert!(!sa.signature.classical_sig.is_empty());
    assert_eq!(sa.size_bytes, 24);

    signer.verify(&path, &sa).expect("Valid artifact must verify OK");
}

#[test]
fn supply_chain_tamper_detected() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_dsa_keypair().unwrap();
    let signer = ArtifactSigner::new(&engine, &kp);
    let (_dir, path) = make_temp_artifact(b"original content");

    let sa = signer.sign(&path, None).unwrap();

    // Adultera o arquivo
    std::fs::write(&path, b"MALICIOUS PAYLOAD").unwrap();
    let result = signer.verify(&path, &sa);
    assert!(result.is_err(), "Tampered artifact must fail verification");

    // Garante que é hash mismatch (não pânico ou outro erro)
    match result.unwrap_err() {
        SupplyChainError::HashMismatch { .. } => {}
        e => panic!("Expected HashMismatch, got: {e}"),
    }
}

#[test]
fn supply_chain_size_mismatch_detected() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_dsa_keypair().unwrap();
    let signer = ArtifactSigner::new(&engine, &kp);
    let (_dir, path) = make_temp_artifact(b"12345678");

    let sa = signer.sign(&path, None).unwrap();
    std::fs::write(&path, b"123456789abcdef").unwrap(); // tamanho diferente
    let result = signer.verify(&path, &sa);

    assert!(result.is_err());
    match result.unwrap_err() {
        SupplyChainError::SizeMismatch { .. } | SupplyChainError::HashMismatch { .. } => {}
        e => panic!("Expected size or hash mismatch, got: {e}"),
    }
}

#[test]
fn supply_chain_sign_nonexistent_fails() {
    let engine = PqcEngine::new();
    let kp     = engine.generate_dsa_keypair().unwrap();
    let signer = ArtifactSigner::new(&engine, &kp);
    let result = signer.sign(std::path::Path::new("/nonexistent/path.bin"), None);
    assert!(matches!(result, Err(SupplyChainError::ArtifactNotFound(_))));
}

#[test]
fn supply_chain_attestation_valid() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let builder = AttestationBuilder::new(&engine, &kp, "test-builder-ci");

    let (_dir, art) = make_temp_artifact(b"release build");
    let att = builder.attest(&[art.as_path()], Some("https://github.com/test/repo"), None, None).unwrap();

    assert_eq!(att.subject.len(), 1);
    assert_eq!(att.builder_id, "test-builder-ci");
    assert!(att.signature.is_some());

    builder.verify(&att).expect("Valid attestation must verify");
}

#[test]
fn supply_chain_tampered_attestation_rejected() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let builder = AttestationBuilder::new(&engine, &kp, "test-builder");

    let (_dir, art) = make_temp_artifact(b"build output");
    let mut att = builder.attest(&[art.as_path()], None, None, None).unwrap();

    // Adultera o payload
    att.builder_id = "evil-attacker".to_string();
    let result = builder.verify(&att);
    assert!(result.is_err(), "Tampered attestation must fail");
}

#[test]
fn supply_chain_unsigned_attestation_rejected() {
    let engine  = PqcEngine::new();
    let kp      = engine.generate_dsa_keypair().unwrap();
    let builder = AttestationBuilder::new(&engine, &kp, "test");

    let (_dir, art) = make_temp_artifact(b"build");
    let mut att = builder.attest(&[art.as_path()], None, None, None).unwrap();
    att.signature = None;

    let result = builder.verify(&att);
    assert!(matches!(result, Err(SupplyChainError::UnsignedAttestation)));
}

// ════════════════════════════════════════════════════════════════════════════
// PILAR 4 — ZERO TRUST
// ════════════════════════════════════════════════════════════════════════════

fn make_jwt_setup() -> (PqcEngine, KeyRegistry) {
    let engine   = PqcEngine::new();
    let registry = KeyRegistry::new(PqcEngine::new()).unwrap();
    (engine, registry)
}

#[test]
fn zero_trust_jwt_issue_and_verify() {
    let (engine, registry) = make_jwt_setup();
    let mut mgr = PqcJwtManager::new(&engine, &registry);

    let token  = mgr.issue("alice@example.com", HashMap::new(), 3600, "api.test", "qsec").unwrap();
    let claims = mgr.verify(&token, "api.test", None).unwrap();

    assert_eq!(claims.sub, "alice@example.com");
    assert_eq!(claims.aud, "api.test");
    assert!(claims.qsec.pqc);
}

#[test]
fn zero_trust_jwt_has_4_parts() {
    let (engine, registry) = make_jwt_setup();
    let mgr   = PqcJwtManager::new(&engine, &registry);
    let token = mgr.issue("user", HashMap::new(), 3600, "", "qsec").unwrap();
    assert_eq!(token.split('.').count(), 4, "PQC-JWT must have 4 parts");
}

#[test]
fn zero_trust_jwt_expired_rejected() {
    let (engine, registry) = make_jwt_setup();
    let mgr   = PqcJwtManager::new(&engine, &registry);
    let token = mgr.issue("user", HashMap::new(), -1, "", "qsec").unwrap();

    let result = mgr.verify(&token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::TokenExpired { .. })));
}

#[test]
fn zero_trust_jwt_revoked_rejected() {
    let (engine, registry) = make_jwt_setup();
    let mut mgr = PqcJwtManager::new(&engine, &registry);

    let token = mgr.issue("user", HashMap::new(), 3600, "", "qsec").unwrap();
    mgr.revoke(&token);

    let result = mgr.verify(&token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::TokenRevoked { .. })));
}

#[test]
fn zero_trust_jwt_algorithm_none_rejected() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (engine, registry) = make_jwt_setup();
    let mgr = PqcJwtManager::new(&engine, &registry);

    let fake_header  = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"none","kid":"fake"}"#);
    let fake_payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"hacker","jti":"x","exp":9999999999,"iat":1}"#);
    let fake_token   = format!("{fake_header}.{fake_payload}.fakesig.fakepqcsig");

    let result = mgr.verify(&fake_token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::InsecureAlgorithm { .. })));
}

#[test]
fn zero_trust_jwt_rs256_rejected() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (engine, registry) = make_jwt_setup();
    let mgr = PqcJwtManager::new(&engine, &registry);

    let fake_header  = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"RS256","kid":"fake"}"#);
    let fake_payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user","jti":"x","exp":9999999999,"iat":1}"#);
    let fake_token   = format!("{fake_header}.{fake_payload}.fakesig.fakepqcsig");

    let result = mgr.verify(&fake_token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::InsecureAlgorithm { .. })));
}

#[test]
fn zero_trust_jwt_hs256_rejected() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (engine, registry) = make_jwt_setup();
    let mgr = PqcJwtManager::new(&engine, &registry);

    let fake_header  = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"HS256","kid":"fake"}"#);
    let fake_payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"user","jti":"x","exp":9999999999,"iat":1}"#);
    let fake_token   = format!("{fake_header}.{fake_payload}.fakesig.fakepqcsig");

    let result = mgr.verify(&fake_token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::InsecureAlgorithm { .. })));
}

#[test]
fn zero_trust_jwt_wrong_part_count_rejected() {
    let (engine, registry) = make_jwt_setup();
    let mgr = PqcJwtManager::new(&engine, &registry);

    let result = mgr.verify("header.payload.sig", "", None); // 3 partes — inválido
    assert!(matches!(result, Err(ZeroTrustError::InvalidTokenFormat { got: 3 })));
}

#[test]
fn zero_trust_jwt_audience_mismatch_rejected() {
    let (engine, registry) = make_jwt_setup();
    let mgr   = PqcJwtManager::new(&engine, &registry);
    let token = mgr.issue("user", HashMap::new(), 3600, "api.correct.com", "qsec").unwrap();

    let result = mgr.verify(&token, "api.wrong.com", None);
    assert!(matches!(result, Err(ZeroTrustError::AudienceMismatch { .. })));
}

#[test]
fn zero_trust_jwt_required_claims_enforced() {
    let (engine, registry) = make_jwt_setup();
    let mgr   = PqcJwtManager::new(&engine, &registry);
    let mut extra = HashMap::new();
    extra.insert("role".to_string(), serde_json::Value::String("admin".to_string()));
    let token = mgr.issue("user", extra, 3600, "", "qsec").unwrap();

    // Claim correto — deve passar
    let mut required = HashMap::new();
    required.insert("role".to_string(), serde_json::Value::String("admin".to_string()));
    assert!(mgr.verify(&token, "", Some(&required)).is_ok());

    // Claim errado — deve falhar
    let mut wrong = HashMap::new();
    wrong.insert("role".to_string(), serde_json::Value::String("user".to_string()));
    assert!(mgr.verify(&token, "", Some(&wrong)).is_err());
}

#[test]
fn zero_trust_jwt_revoke_by_jti() {
    let (engine, registry) = make_jwt_setup();
    let mut mgr = PqcJwtManager::new(&engine, &registry);

    let token  = mgr.issue("user", HashMap::new(), 3600, "", "qsec").unwrap();
    let claims = mgr.verify(&token, "", None).unwrap();
    let jti    = claims.jti.clone();

    mgr.revoke(&jti); // Revoga pelo JTI diretamente
    let result = mgr.verify(&token, "", None);
    assert!(matches!(result, Err(ZeroTrustError::TokenRevoked { .. })));
}

#[test]
fn zero_trust_key_registry_initial_state() {
    let registry = KeyRegistry::new(PqcEngine::new()).unwrap();
    let report   = registry.status_report();
    assert!(!report.is_empty(), "Registry must have at least one key");
    assert!(report.iter().any(|k| k.is_active), "Must have an active key");
}

#[test]
fn zero_trust_key_registry_get_active_key() {
    let registry = KeyRegistry::new(PqcEngine::new()).unwrap();
    let kp = registry.active_signing_key().unwrap();
    assert!(kp.algorithm.starts_with("Ed25519"));
}

#[test]
fn zero_trust_key_registry_revoke_generates_new() {
    let mut registry = KeyRegistry::new(PqcEngine::new()).unwrap();
    let old_kid = registry.active_signing_key().unwrap().key_id.clone();

    registry.revoke_key(&old_kid).unwrap();

    let new_kp = registry.active_signing_key().unwrap();
    assert_ne!(new_kp.key_id, old_kid, "New key must have different ID");
}

#[test]
fn zero_trust_key_registry_revoked_key_unavailable() {
    let mut registry = KeyRegistry::new(PqcEngine::new()).unwrap();
    let kid = registry.active_signing_key().unwrap().key_id.clone();

    registry.revoke_key(&kid).unwrap();
    assert!(registry.get_key(&kid).is_none(), "Revoked key must not be retrievable");
}

#[test]
fn zero_trust_apikey_create_and_verify() {
    let mut mgr = ApiKeyManager::new();
    let (key_id, raw_key) = mgr.create("service-ml", vec!["read".into(), "write".into()], Some(90)).unwrap();

    assert!(key_id.starts_with("kid_"));
    assert!(raw_key.starts_with("qsec_"));

    let entry = mgr.verify(&raw_key, None).unwrap();
    assert_eq!(entry.key_id, key_id);
}

#[test]
fn zero_trust_apikey_scope_enforced() {
    let mut mgr = ApiKeyManager::new();
    let (_, raw) = mgr.create("svc", vec!["models:read".into()], Some(30)).unwrap();

    // Scope correto — deve passar
    assert!(mgr.verify(&raw, Some("models:read")).is_ok());

    // Scope faltando — deve falhar
    let result = mgr.verify(&raw, Some("admin:all"));
    assert!(matches!(result, Err(ZeroTrustError::InsufficientScope { .. })));
}

#[test]
fn zero_trust_apikey_revoke_blocks_access() {
    let mut mgr = ApiKeyManager::new();
    let (key_id, raw) = mgr.create("svc", vec![], Some(30)).unwrap();

    mgr.revoke(&key_id).unwrap();
    let result = mgr.verify(&raw, None);
    assert!(matches!(result, Err(ZeroTrustError::ApiKeyRevoked)));
}

#[test]
fn zero_trust_apikey_wrong_key_rejected() {
    let mut mgr = ApiKeyManager::new();
    mgr.create("svc", vec![], Some(30)).unwrap();

    let result = mgr.verify("qsec_0000000000000000000000000000000000000000000000000000000000000000", None);
    assert!(result.is_err());
}

#[test]
fn zero_trust_apikey_no_prefix_rejected() {
    let mut mgr = ApiKeyManager::new();
    let result  = mgr.verify("invalid_key_without_qsec_prefix", None);
    assert!(matches!(result, Err(ZeroTrustError::InvalidApiKeyFormat)));
}

#[test]
fn zero_trust_apikey_list_never_exposes_hash() {
    let mut mgr = ApiKeyManager::new();
    mgr.create("svc-a", vec!["read".into()], Some(30)).unwrap();
    mgr.create("svc-b", vec!["write".into()], Some(90)).unwrap();

    let list = mgr.list();
    assert_eq!(list.len(), 2);

    // Serializa e garante que nenhum hash vaza
    let json = serde_json::to_string(&list).unwrap();
    assert!(!json.contains("key_hash"), "key_hash must never be serialized");
}

// ════════════════════════════════════════════════════════════════════════════
// PROPRIEDADES DE SEGURANÇA — testes cruzados
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn security_revocation_checked_before_expiry() {
    // Garante que tokens revogados são rejeitados mesmo se ainda válidos no tempo.
    // Ordem correta: revogação ANTES de expiração (evita oracle de timing).
    let (engine, registry) = make_jwt_setup();
    let mut mgr = PqcJwtManager::new(&engine, &registry);

    let token = mgr.issue("user", HashMap::new(), 9999, "", "qsec").unwrap();
    mgr.revoke(&token);

    let result = mgr.verify(&token, "", None);
    // Deve ser Revoked, não Expired
    assert!(matches!(result, Err(ZeroTrustError::TokenRevoked { .. })),
            "Revocation must be checked BEFORE expiry");
}

#[test]
fn security_supply_chain_sha3_mismatch_detected_before_signature() {
    // Garante que SHA3-256 mismatch é detectado antes de tentar verificar a assinatura.
    let engine = PqcEngine::new();
    let kp     = engine.generate_dsa_keypair().unwrap();
    let signer = ArtifactSigner::new(&engine, &kp);
    let (_dir, path) = make_temp_artifact(b"original");

    let sa = signer.sign(&path, None).unwrap();
    std::fs::write(&path, b"TAMPERED").unwrap();

    let result = signer.verify(&path, &sa);
    // Deve ser HashMismatch, não SignatureVerification
    assert!(matches!(result, Err(SupplyChainError::HashMismatch { .. })),
            "SHA3 mismatch must be detected before signature check");
}

#[test]
fn security_multiple_jwt_tokens_independent() {
    // Revogação de um token não deve afetar outros tokens.
    let (engine, registry) = make_jwt_setup();
    let mut mgr = PqcJwtManager::new(&engine, &registry);

    let token1 = mgr.issue("user1", HashMap::new(), 3600, "", "qsec").unwrap();
    let token2 = mgr.issue("user2", HashMap::new(), 3600, "", "qsec").unwrap();

    mgr.revoke(&token1);

    assert!(mgr.verify(&token1, "", None).is_err(), "token1 deve ser revogado");
    assert!(mgr.verify(&token2, "", None).is_ok(), "token2 nao deve ser afetado");
}
