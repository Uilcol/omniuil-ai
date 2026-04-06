//! Hierarquia de erros do QSEC.
//!
//! Todos os erros são tipados com `thiserror` para mensagens claras
//! e tratamento idiomático com `?` operator.

use thiserror::Error;

/// Erro principal do QSEC — agrega todos os subsistemas.
#[derive(Debug, Error)]
pub enum QsecError {
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Scanner error: {0}")]
    Scanner(#[from] ScannerError),

    #[error("Supply chain error: {0}")]
    SupplyChain(#[from] SupplyChainError),

    #[error("Zero trust error: {0}")]
    ZeroTrust(#[from] ZeroTrustError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Erros do motor PQC.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed — possible tampering or wrong key")]
    DecryptionFailed,

    #[error("Signature creation failed: {0}")]
    SigningFailed(String),

    #[error("Signature verification failed — message or key mismatch")]
    InvalidSignature,

    #[error("KEM encapsulation failed: {0}")]
    KemEncapsulation(String),

    #[error("KEM decapsulation failed — possible tampering")]
    KemDecapsulation,

    #[error("Key has been zeroized and cannot be used")]
    ZeroizedKey,

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("PQC backend not available — enable 'liboqs' feature")]
    BackendUnavailable,
}

/// Erros do scanner de criptografia.
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("Failed to read file {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid UTF-8 in file {path}")]
    InvalidUtf8 { path: String },

    #[error("Regex compilation failed: {0}")]
    RegexCompilation(String),
}

/// Erros da supply chain.
#[derive(Debug, Error)]
pub enum SupplyChainError {
    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),

    #[error("Hash mismatch for {artifact} — possible tampering. Expected: {expected}, got: {actual}")]
    HashMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },

    #[error("Size mismatch for {artifact}: expected {expected} bytes, got {actual}")]
    SizeMismatch {
        artifact: String,
        expected: u64,
        actual: u64,
    },

    #[error("Signature verification failed for {artifact}")]
    SignatureVerification { artifact: String },

    #[error("Attestation has no signature")]
    UnsignedAttestation,

    #[error("Attestation verification failed: {0}")]
    AttestationVerification(String),

    #[error("SBOM generation failed: {0}")]
    SbomGeneration(String),

    #[error("Manifest write failed: {0}")]
    ManifestWrite(String),
}

/// Erros do subsistema Zero Trust.
#[derive(Debug, Error)]
pub enum ZeroTrustError {
    // JWT
    #[error("Invalid token format: expected 4 parts (header.payload.ed25519_sig.mldsa_sig), got {got}")]
    InvalidTokenFormat { got: usize },

    #[error("Insecure or missing algorithm rejected: '{algorithm}'")]
    InsecureAlgorithm { algorithm: String },

    #[error("Token has been revoked (jti: {jti})")]
    TokenRevoked { jti: String },

    #[error("Token expired at {expired_at}")]
    TokenExpired { expired_at: String },

    #[error("Token issued in the future — possible replay attack (iat: {iat})")]
    FutureIssuedAt { iat: i64 },

    #[error("Missing required claim: '{claim}'")]
    MissingClaim { claim: String },

    #[error("Audience mismatch: expected '{expected}', got '{actual}'")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Unknown or revoked key ID: '{kid}'")]
    UnknownKeyId { kid: String },

    #[error("JWT signature verification failed")]
    JwtSignatureInvalid,

    #[error("JWT decode failed: {0}")]
    JwtDecode(String),

    // Keys
    #[error("Key registry is empty — no active keys")]
    NoActiveKey,

    #[error("Key not found: {kid}")]
    KeyNotFound { kid: String },

    #[error("Key has been revoked: {kid}")]
    KeyRevoked { kid: String },

    // API Keys
    #[error("API key has invalid format")]
    InvalidApiKeyFormat,

    #[error("API key not found or invalid")]
    ApiKeyInvalid,

    #[error("API key has been revoked")]
    ApiKeyRevoked,

    #[error("API key has expired")]
    ApiKeyExpired,

    #[error("Insufficient scope: required '{required}'")]
    InsufficientScope { required: String },
}

/// Tipo `Result` conveniente para QSEC.
pub type QsecResult<T> = Result<T, QsecError>;
pub type CryptoResult<T> = Result<T, CryptoError>;
pub type ScannerResult<T> = Result<T, ScannerError>;
pub type SupplyChainResult<T> = Result<T, SupplyChainError>;
pub type ZeroTrustResult<T> = Result<T, ZeroTrustError>;
