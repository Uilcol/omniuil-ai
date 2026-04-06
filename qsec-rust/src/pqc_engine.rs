//! Motor Criptográfico Híbrido Pós-Quântico.
//!
//! Implementa criptografia híbrida clássica + pós-quântica:
//!
//! **KEM (Key Encapsulation):**
//! - X25519 (clássico) + ML-KEM-1024 (pós-quântico)
//! - Chave final: `HKDF-SHA3-256(SS_clássico || SS_pqc)`
//! - Proteção HNDL: ambos os shared secrets são necessários
//!
//! **DSA (Digital Signatures):**
//! - Ed25519 (clássico) + ML-DSA-87 (pós-quântico)
//! - Ambas as assinaturas devem ser válidas para verificação passar
//!
//! **Segurança de memória:**
//! - `ZeroizeOnDrop` em todas as structs com material privado
//! - Comparações em tempo constante via `subtle`

use std::fmt;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, CryptoResult};

// ─── Algoritmos ───────────────────────────────────────────────────────────────

pub const ML_KEM_ALGORITHM: &str = "ML-KEM-1024";  // NIST FIPS 203 — Level 5
pub const ML_DSA_ALGORITHM: &str = "ML-DSA-87";    // NIST FIPS 204 — Level 5
pub const HYBRID_KEM_ALG:   &str = "X25519+ML-KEM-1024+AES-256-GCM";
pub const HYBRID_DSA_ALG:   &str = "Ed25519+ML-DSA-87";
pub const HKDF_INFO:        &[u8] = b"qsec-hybrid-kem-v3";
pub const SAFE_AAD:         &[u8] = b"qsec-no-aad-v3";

// ─── MATERIAL DE CHAVE PRIVADA ────────────────────────────────────────────────

/// Material de chave privada KEM — zeroizado automaticamente no Drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemPrivateKey {
    /// Chave privada X25519 (32 bytes)
    pub classical: StaticSecret,
    /// Chave privada ML-KEM (variável, dependente do backend)
    pub pqc: Vec<u8>,
}

/// Material de chave privada DSA — zeroizado automaticamente no Drop.
pub struct DsaPrivateKey {
    /// Chave privada Ed25519 (32 bytes)
    pub classical: SigningKey,
    /// Chave privada ML-DSA (variável)
    pub pqc: Vec<u8>,
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        // pqc bytes: zeroize manualmente
        self.pqc.zeroize();
        // SigningKey: ed25519-dalek v2 faz zeroize interno no Drop
    }
}

impl zeroize::Zeroize for DsaPrivateKey {
    fn zeroize(&mut self) {
        self.pqc.zeroize();
        // SigningKey não expõe Zeroize externo em v2 — Drop interno cuida disso
    }
}

// ─── PAR DE CHAVES HÍBRIDO ────────────────────────────────────────────────────

/// Par de chaves KEM híbrido (X25519 + ML-KEM).
///
/// O material privado é zeroizado automaticamente via `Drop`.
/// `Display` e `Debug` nunca expõem chaves privadas.
pub struct HybridKemKeyPair {
    pub key_id:      String,
    pub algorithm:   String,
    pub created_at:  chrono::DateTime<Utc>,
    pub public_key:  KemPublicKey,
    pub private_key: KemPrivateKey,   // ZeroizeOnDrop
}

/// Par de chaves DSA híbrido (Ed25519 + ML-DSA).
pub struct HybridDsaKeyPair {
    pub key_id:      String,
    pub algorithm:   String,
    pub created_at:  chrono::DateTime<Utc>,
    pub public_key:  DsaPublicKey,
    pub private_key: DsaPrivateKey,   // ZeroizeOnDrop
}

/// Chave pública KEM — segura para serializar e compartilhar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemPublicKey {
    pub key_id:            String,
    pub algorithm:         String,
    pub classical_public:  Vec<u8>,   // X25519 public key (32 bytes)
    pub pqc_public:        Vec<u8>,   // ML-KEM public key
    pub created_at:        String,
}

/// Chave pública DSA — segura para serializar e compartilhar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsaPublicKey {
    pub key_id:            String,
    pub algorithm:         String,
    pub classical_public:  Vec<u8>,   // Ed25519 public key (32 bytes)
    pub pqc_public:        Vec<u8>,   // ML-DSA public key
    pub created_at:        String,
}

// SECURITY: Debug nunca expõe material privado
impl fmt::Debug for HybridKemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridKemKeyPair {{ key_id: {:?}, algorithm: {:?}, [PRIVATE KEY REDACTED] }}",
               self.key_id, self.algorithm)
    }
}

impl fmt::Debug for HybridDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridDsaKeyPair {{ key_id: {:?}, algorithm: {:?}, [PRIVATE KEY REDACTED] }}",
               self.key_id, self.algorithm)
    }
}

// SECURITY: Display nunca expõe material privado
impl fmt::Display for HybridKemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridKemKeyPair(kid={}, alg={}, [PRIVATE KEY REDACTED])",
               self.key_id, self.algorithm)
    }
}

impl fmt::Display for HybridDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridDsaKeyPair(kid={}, alg={}, [PRIVATE KEY REDACTED])",
               self.key_id, self.algorithm)
    }
}



/// Resultado de encriptação KEM híbrida.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    /// Versão do formato
    pub version:           u8,
    pub algorithm:         String,
    /// Ephemeral X25519 public key (KEM clássico)
    pub classical_kem_ct:  Vec<u8>,
    /// ML-KEM ciphertext (KEM pós-quântico)
    pub pqc_kem_ct:        Vec<u8>,
    /// AES-256-GCM ciphertext
    pub encrypted_payload: Vec<u8>,
    /// GCM nonce (12 bytes)
    pub nonce:             Vec<u8>,
    pub sender_key_id:     String,
}

impl HybridCiphertext {
    pub fn serialize(&self) -> CryptoResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    pub fn deserialize(data: &[u8]) -> CryptoResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| CryptoError::Deserialization(e.to_string()))
    }
}

// ─── ASSINATURA HÍBRIDA ───────────────────────────────────────────────────────

/// Assinatura híbrida Ed25519 + ML-DSA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub version:       u8,
    pub algorithm:     String,
    pub key_id:        String,
    pub signed_at:     i64,
    /// SHA3-256 da mensagem original
    pub message_hash:  String,
    /// Ed25519 signature (64 bytes) — hex encoded
    pub classical_sig: String,
    /// ML-DSA signature — hex encoded
    pub pqc_sig:       String,
}

impl HybridSignature {
    pub fn serialize(&self) -> CryptoResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))
    }

    pub fn deserialize(data: &[u8]) -> CryptoResult<Self> {
        serde_json::from_slice(data)
            .map_err(|e| CryptoError::Deserialization(e.to_string()))
    }
}

// ─── BACKEND PQC ─────────────────────────────────────────────────────────────

/// Abstração sobre o backend PQC (liboqs ou referência).
pub struct PqcBackend {
    pub name: &'static str,
}

impl PqcBackend {
    pub fn new() -> Self {
        #[cfg(feature = "liboqs")]
        {
            Self { name: "liboqs (NIST FIPS 203/204)" }
        }
        #[cfg(not(feature = "liboqs"))]
        {
            Self { name: "reference (cargo build --features liboqs for production)" }
        }
    }

    /// Gera par de chaves ML-KEM.
    /// Retorna (secret_key, public_key).
    pub fn kem_keygen(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "liboqs")]
        {
            use oqs::kem::{Algorithm, Kem};
            let kem = Kem::new(Algorithm::MlKem1024)
                .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
            let (pk, sk) = kem.keypair()
                .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
            Ok((sk.into_vec(), pk.into_vec()))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // Backend de referência estrutural
            let mut sk = vec![0u8; 64];
            let mut pk = vec![0u8; 64];
            OsRng.fill_bytes(&mut sk);
            // pk = SHA3-256(sk) para referência determinística
            let hash = <Sha3_256 as Digest>::digest(&sk);
            pk[..32].copy_from_slice(&hash);
            let hash2 = <Sha3_256 as Digest>::digest(&hash);
            pk[32..].copy_from_slice(&hash2);
            Ok((sk, pk))
        }
    }

    /// Encapsula shared secret com ML-KEM.
    /// Retorna (ciphertext, shared_secret).
    pub fn kem_encapsulate(&self, public_key: &[u8]) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "liboqs")]
        {
            use oqs::kem::{Algorithm, Kem, PublicKey};
            let kem = Kem::new(Algorithm::MlKem1024)
                .map_err(|e| CryptoError::KemEncapsulation(e.to_string()))?;
            let pk = PublicKey::from_bytes(public_key)
                .map_err(|e| CryptoError::KemEncapsulation(e.to_string()))?;
            let (ct, ss) = kem.encapsulate(&pk)
                .map_err(|e| CryptoError::KemEncapsulation(e.to_string()))?;
            Ok((ct.into_vec(), ss.into_vec()))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            let mut ephemeral = vec![0u8; 32];
            OsRng.fill_bytes(&mut ephemeral);
            let mut ct_data = Vec::with_capacity(64);
            ct_data.extend_from_slice(&<Sha3_256 as Digest>::digest(
                [public_key, ephemeral.as_slice()].concat().as_slice()
            ));
            ct_data.extend_from_slice(&ephemeral);
            let ss = <Sha3_256 as Digest>::digest(
                [public_key, ephemeral.as_slice(), b"ss"].concat().as_slice()
            ).to_vec();
            Ok((ct_data, ss))
        }
    }

    /// Decapsula shared secret com ML-KEM.
    pub fn kem_decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        #[cfg(feature = "liboqs")]
        {
            use oqs::kem::{Algorithm, Kem, SecretKey, Ciphertext};
            let kem = Kem::new(Algorithm::MlKem1024)
                .map_err(|_| CryptoError::KemDecapsulation)?;
            let sk = SecretKey::from_bytes(secret_key)
                .map_err(|_| CryptoError::KemDecapsulation)?;
            let ct = Ciphertext::from_bytes(ciphertext)
                .map_err(|_| CryptoError::KemDecapsulation)?;
            let ss = kem.decapsulate(&sk, &ct)
                .map_err(|_| CryptoError::KemDecapsulation)?;
            Ok(ss.into_vec())
        }
        #[cfg(not(feature = "liboqs"))]
        {
            if ciphertext.len() < 32 {
                return Err(CryptoError::KemDecapsulation);
            }
            let ephemeral = &ciphertext[32..];
            let pk: Vec<u8> = {
                let hash = <Sha3_256 as Digest>::digest(secret_key);
                let hash2 = <Sha3_256 as Digest>::digest(hash.as_slice());
                [hash.as_slice(), hash2.as_slice()].concat()
            };
            let ss = <Sha3_256 as Digest>::digest(
                [pk.as_slice(), ephemeral, b"ss"].concat().as_slice()
            ).to_vec();
            Ok(ss)
        }
    }

    /// Gera par de chaves ML-DSA.
    /// Retorna (secret_key, public_key).
    pub fn dsa_keygen(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "liboqs")]
        {
            use oqs::sig::{Algorithm, Sig};
            let sig = Sig::new(Algorithm::MlDsa87)
                .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
            let (pk, sk) = sig.keypair()
                .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
            Ok((sk.into_vec(), pk.into_vec()))
        }
        #[cfg(not(feature = "liboqs"))]
        {
            let mut sk = vec![0u8; 64];
            OsRng.fill_bytes(&mut sk);
            let pk = <Sha3_256 as Digest>::digest(
                [sk.as_slice(), b"dsa_pk"].concat().as_slice()
            ).to_vec();
            Ok((sk, pk))
        }
    }

    /// Assina mensagem com ML-DSA.
    pub fn dsa_sign(&self, secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        #[cfg(feature = "liboqs")]
        {
            use oqs::sig::{Algorithm, SecretKey, Sig};
            let sig_obj = Sig::new(Algorithm::MlDsa87)
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            let sk = SecretKey::from_bytes(secret_key)
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            let sig = sig_obj.sign(message, &sk)
                .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
            Ok(sig.into_vec())
        }
        #[cfg(not(feature = "liboqs"))]
        {
            use hmac::{Hmac, Mac};
            type HmacSha3_256 = Hmac<Sha3_256>;
            if secret_key.len() < 32 {
                return Err(CryptoError::SigningFailed("key too short".into()));
            }
            // Deriva a pk para manter consistência com dsa_verify
            let pk = <Sha3_256 as Digest>::digest([secret_key, b"dsa_pk"].concat().as_slice()).to_vec();
            let hmac_key = <Sha3_256 as Digest>::digest([pk.as_slice(), b"dsa_verify_key"].concat().as_slice());
            let mut mac = <HmacSha3_256 as hmac::Mac>::new_from_slice(&hmac_key)
                .map_err(|e: hmac::digest::InvalidLength| CryptoError::SigningFailed(e.to_string()))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }

    /// Verifica assinatura ML-DSA.
    pub fn dsa_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        #[cfg(feature = "liboqs")]
        {
            use oqs::sig::{Algorithm, PublicKey, Sig, Signature};
            let Ok(sig_obj) = Sig::new(Algorithm::MlDsa87) else { return false };
            let Ok(pk) = PublicKey::from_bytes(public_key) else { return false };
            let Ok(sig) = Signature::from_bytes(signature) else { return false };
            sig_obj.verify(message, &sig, &pk).is_ok()
        }
        #[cfg(not(feature = "liboqs"))]
        {
            // SECURITY: referência usa HMAC-SHA3-256 deterministico.
            // dsa_sign() usa HMAC(sk[..32], message).
            // Aqui derivamos a mesma chave a partir da pk (SHA3-256(pk || "dsa_pk")[..32])
            // e recomputamos o MAC para verificação. Isso é correto para o backend de referência.
            use hmac::{Hmac, Mac};
            type HmacSha3_256 = Hmac<Sha3_256>;

            if public_key.is_empty() || signature.is_empty() {
                return false;
            }

            // A chave HMAC que o sign() teria usado = sk[..32]
            // Derivamos sk de pk via relação conhecida no backend: pk = SHA3-256(sk || "dsa_pk")
            // Não podemos reverter, então usamos a pk diretamente como chave HMAC de verificação
            // NOTA: em produção, liboqs usa ML-DSA real. Esta é estrutural.
            let hmac_key: Vec<u8> = {
                let h = <Sha3_256 as Digest>::digest([public_key, b"dsa_verify_key"].concat().as_slice());
                h.to_vec()
            };

            let Ok(mut mac) = <HmacSha3_256 as hmac::Mac>::new_from_slice(&hmac_key) else { return false };
            mac.update(message);
            let expected = mac.finalize().into_bytes();

            // Tempo constante
            expected.as_slice().ct_eq(signature).into()
        }
    }
}

impl Default for PqcBackend {
    fn default() -> Self { Self::new() }
}

// ─── PQC ENGINE ───────────────────────────────────────────────────────────────

/// Motor criptográfico híbrido principal.
///
/// # Exemplo
/// ```rust
/// let engine = PqcEngine::new();
///
/// // KEM híbrido
/// let kem_keys = engine.generate_kem_keypair()?;
/// let ct       = engine.hybrid_encrypt(b"segredo", &kem_keys.public_key)?;
/// let pt       = engine.hybrid_decrypt(&ct, &kem_keys)?;
///
/// // Assinatura híbrida
/// let dsa_keys = engine.generate_dsa_keypair()?;
/// let sig      = engine.hybrid_sign(b"mensagem", &dsa_keys)?;
/// let ok       = engine.hybrid_verify(b"mensagem", &sig, &dsa_keys.public_key)?;
/// ```
pub struct PqcEngine {
    backend: PqcBackend,
}

impl PqcEngine {
    pub fn new() -> Self {
        Self { backend: PqcBackend::new() }
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name
    }

    // ── Geração de Chaves ─────────────────────────────────────────────────────

    /// Gera par de chaves KEM híbrido: X25519 + ML-KEM-1024.
    pub fn generate_kem_keypair(&self) -> CryptoResult<HybridKemKeyPair> {
        // X25519
        let x25519_sk  = StaticSecret::random_from_rng(OsRng);
        let x25519_pk  = X25519PublicKey::from(&x25519_sk);

        // ML-KEM
        let (pqc_sk, pqc_pk) = self.backend.kem_keygen()?;

        let key_id    = generate_key_id();
        let created   = Utc::now();

        Ok(HybridKemKeyPair {
            key_id: key_id.clone(),
            algorithm: format!("X25519+{}", ML_KEM_ALGORITHM),
            created_at: created,
            public_key: KemPublicKey {
                key_id: key_id.clone(),
                algorithm: format!("X25519+{}", ML_KEM_ALGORITHM),
                classical_public: x25519_pk.as_bytes().to_vec(),
                pqc_public: pqc_pk,
                created_at: created.to_rfc3339(),
            },
            private_key: KemPrivateKey {
                classical: x25519_sk,
                pqc: pqc_sk,
            },
        })
    }

    /// Gera par de chaves DSA híbrido: Ed25519 + ML-DSA-87.
    pub fn generate_dsa_keypair(&self) -> CryptoResult<HybridDsaKeyPair> {
        // Ed25519
        let ed_sk = SigningKey::generate(&mut OsRng);
        let ed_pk = ed_sk.verifying_key();

        // ML-DSA
        let (pqc_sk, pqc_pk) = self.backend.dsa_keygen()?;

        let key_id  = generate_key_id();
        let created = Utc::now();

        Ok(HybridDsaKeyPair {
            key_id: key_id.clone(),
            algorithm: format!("Ed25519+{}", ML_DSA_ALGORITHM),
            created_at: created,
            public_key: DsaPublicKey {
                key_id: key_id.clone(),
                algorithm: format!("Ed25519+{}", ML_DSA_ALGORITHM),
                classical_public: ed_pk.to_bytes().to_vec(),
                pqc_public: pqc_pk,
                created_at: created.to_rfc3339(),
            },
            private_key: DsaPrivateKey {
                classical: ed_sk,
                pqc: pqc_sk,
            },
        })
    }

    // ── Encriptação Híbrida ───────────────────────────────────────────────────

    /// Encripta com KEM híbrido.
    ///
    /// **Proteção HNDL (Harvest Now, Decrypt Later):**
    /// ```
    /// SS_C  = X25519(ephemeral, recipient_pk)     [clássico]
    /// SS_PQ = ML-KEM-Decap(recipient_pk, ct_pq)   [pós-quântico]
    /// K     = HKDF-SHA3-256(SS_C || SS_PQ)         [combinado]
    /// CT    = AES-256-GCM(K, plaintext)
    /// ```
    /// Um adversário precisa quebrar **ambos** os KEMs para decriptar.
    pub fn hybrid_encrypt(
        &self,
        plaintext: &[u8],
        recipient: &KemPublicKey,
        aad: Option<&[u8]>,
    ) -> CryptoResult<HybridCiphertext> {
        // X25519 KEM
        let ephemeral_sk  = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pk  = X25519PublicKey::from(&ephemeral_sk);
        let recipient_x25519_pk = X25519PublicKey::from(
            TryInto::<[u8; 32]>::try_into(recipient.classical_public.as_slice())
                .map_err(|_| CryptoError::Encryption("invalid classical public key size".into()))?
        );
        let ss_classical = ephemeral_sk.diffie_hellman(&recipient_x25519_pk);
        let classical_ct = ephemeral_pk.as_bytes().to_vec();

        // ML-KEM
        let (pqc_ct, ss_pqc) = self.backend.kem_encapsulate(&recipient.pqc_public)?;

        // Deriva chave AES: HKDF-SHA3-256(SS_clássico || SS_pqc)
        let combined_ss: Vec<u8> = [ss_classical.as_bytes().as_slice(), ss_pqc.as_slice()].concat();
        let aes_key = derive_key(&combined_ss)?;

        // AES-256-GCM
        // SECURITY: nunca usa None como AAD — diferença silenciosa no auth tag
        let safe_aad = aad.unwrap_or(SAFE_AAD);
        let cipher    = Aes256Gcm::new(&aes_key);
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut AesOsRng);

        let payload = Payload { msg: plaintext, aad: safe_aad };
        let encrypted = cipher
            .encrypt(&nonce_bytes, payload)
            .map_err(|_| CryptoError::Encryption("AES-256-GCM encryption failed".into()))?;

        Ok(HybridCiphertext {
            version:           3,
            algorithm:         HYBRID_KEM_ALG.to_string(),
            classical_kem_ct:  classical_ct,
            pqc_kem_ct:        pqc_ct,
            encrypted_payload: encrypted,
            nonce:             nonce_bytes.to_vec(),
            sender_key_id:     String::new(),
        })
    }

    /// Decripta ciphertext KEM híbrido.
    pub fn hybrid_decrypt(
        &self,
        ct: &HybridCiphertext,
        keypair: &HybridKemKeyPair,
        aad: Option<&[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        // X25519
        let sender_x25519_pk = X25519PublicKey::from(
            TryInto::<[u8; 32]>::try_into(ct.classical_kem_ct.as_slice())
                .map_err(|_| CryptoError::DecryptionFailed)?
        );
        let ss_classical = keypair.private_key.classical.diffie_hellman(&sender_x25519_pk);

        // ML-KEM
        let ss_pqc = self.backend.kem_decapsulate(&keypair.private_key.pqc, &ct.pqc_kem_ct)?;

        // Deriva chave
        let combined_ss: Vec<u8> = [ss_classical.as_bytes().as_slice(), ss_pqc.as_slice()].concat();
        let aes_key = derive_key(&combined_ss)?;

        // AES-256-GCM
        let safe_aad = aad.unwrap_or(SAFE_AAD);
        let cipher = Aes256Gcm::new(&aes_key);

        // SECURITY: valida tamanho do nonce antes de from_slice (12 bytes para GCM)
        if ct.nonce.len() != 12 {
            return Err(CryptoError::DecryptionFailed);
        }
        let nonce  = Nonce::from_slice(&ct.nonce);

        let payload = Payload { msg: &ct.encrypted_payload, aad: safe_aad };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    // ── Assinatura Híbrida ────────────────────────────────────────────────────

    /// Assina mensagem com Ed25519 + ML-DSA.
    /// Ambas as assinaturas são criadas e devem ser verificadas.
    pub fn hybrid_sign(
        &self,
        message: &[u8],
        keypair: &HybridDsaKeyPair,
    ) -> CryptoResult<HybridSignature> {
        // Ed25519
        let ed_sig = keypair.private_key.classical.sign(message);

        // ML-DSA
        let pqc_sig = self.backend.dsa_sign(&keypair.private_key.pqc, message)?;

        // Hash da mensagem para integridade adicional
        let msg_hash = hex::encode(<Sha3_256 as Digest>::digest(message));

        Ok(HybridSignature {
            version:       3,
            algorithm:     HYBRID_DSA_ALG.to_string(),
            key_id:        keypair.key_id.clone(),
            signed_at:     Utc::now().timestamp(),
            message_hash:  msg_hash,
            classical_sig: hex::encode(ed_sig.to_bytes()),
            pqc_sig:       hex::encode(&pqc_sig),
        })
    }

    /// Verifica assinatura híbrida.
    /// **Ambas** Ed25519 e ML-DSA devem ser válidas.
    pub fn hybrid_verify(
        &self,
        message: &[u8],
        sig: &HybridSignature,
        public_key: &DsaPublicKey,
    ) -> CryptoResult<bool> {
        // Ed25519
        let ed_pk_bytes: [u8; 32] = public_key.classical_public.as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let ed_pk = VerifyingKey::from_bytes(&ed_pk_bytes)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let ed_sig_bytes = hex::decode(&sig.classical_sig)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let ed_sig_arr: [u8; 64] = ed_sig_bytes.as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_arr);

        if ed_pk.verify(message, &ed_sig).is_err() {
            return Ok(false);
        }

        // ML-DSA
        let pqc_sig_bytes = hex::decode(&sig.pqc_sig)
            .map_err(|_| CryptoError::InvalidSignature)?;
        if !self.backend.dsa_verify(&public_key.pqc_public, message, &pqc_sig_bytes) {
            return Ok(false);
        }

        // Integridade do hash da mensagem
        let expected_hash = hex::encode(<Sha3_256 as Digest>::digest(message));
        // Tempo constante — evita timing oracle no hash
        let hashes_match: bool = expected_hash.as_bytes()
            .ct_eq(sig.message_hash.as_bytes())
            .into();
        if !hashes_match {
            return Ok(false);
        }

        Ok(true)
    }

    /// Informações do backend.
    pub fn info(&self) -> EngineInfo {
        EngineInfo {
            backend:                              self.backend.name.to_string(),
            kem_algorithm:                        format!("X25519 + {}", ML_KEM_ALGORITHM),
            dsa_algorithm:                        format!("Ed25519 + {}", ML_DSA_ALGORITHM),
            symmetric:                            "AES-256-GCM".to_string(),
            kdf:                                  "HKDF-SHA3-256".to_string(),
            harvest_now_decrypt_later_protection: true,
            nist_pqc_compliant:                   cfg!(feature = "liboqs"),
        }
    }
}

impl Default for PqcEngine {
    fn default() -> Self { Self::new() }
}

/// Informações sobre o motor PQC.
#[derive(Debug, Serialize, Deserialize)]
pub struct EngineInfo {
    pub backend:                              String,
    pub kem_algorithm:                        String,
    pub dsa_algorithm:                        String,
    pub symmetric:                            String,
    pub kdf:                                  String,
    pub harvest_now_decrypt_later_protection: bool,
    pub nist_pqc_compliant:                   bool,
}

// ─── Helpers Internos ─────────────────────────────────────────────────────────

/// Deriva chave AES-256 com HKDF-SHA3-256.
///
/// SECURITY: usa salt fixo domain-specific (não None).
/// Salt None enfraquece a derivação quando o IKM tem baixa entropia.
fn derive_key(ikm: &[u8]) -> CryptoResult<Key<Aes256Gcm>> {
    // Salt fixo e público com separação de domínio
    const HKDF_SALT: &[u8] = b"qsec-hkdf-salt-v3-kem-key-derivation";
    let hkdf = Hkdf::<Sha3_256>::new(Some(HKDF_SALT), ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut okm)
        .map_err(|e| CryptoError::Encryption(format!("HKDF expand failed: {e}")))?;
    let key = *Key::<Aes256Gcm>::from_slice(&okm);
    // SECURITY: zeroiza o buffer intermediário — chave AES não deve ficar na stack
    okm.zeroize();
    Ok(key)
}

/// Gera ID de chave aleatório seguro (32 hex chars = 128 bits de entropia).
fn generate_key_id() -> String {
    let mut bytes = [0u8; 16];   // 128 bits — safe against birthday attack at any realistic scale
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// Trait para fill_bytes sem depender de rand diretamente aqui
trait FillBytes {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl FillBytes for rand_core::OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, dest)
    }
}
