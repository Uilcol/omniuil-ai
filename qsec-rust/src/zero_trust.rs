//! # Zero Trust Identity — Pilar 4
//!
//! Infraestrutura de identidade digital pós-quântica com Zero Trust.
//!
//! ## Componentes
//!
//! - **[`PqcJwtManager`]** — JWTs de 4 partes (Ed25519 + ML-DSA)
//! - **[`KeyRegistry`]** — rotação automática de chaves com TTL
//! - **[`ApiKeyManager`]** — API keys com hash SHA3-256 (nunca armazena plaintext)
//!
//! ## Ordem de verificação JWT (segura contra timing attacks)
//!
//! ```text
//! 1. Estrutura — exige 4 partes
//! 2. Algoritmo — rejeita none/RS*/HS*/ES*
//! 3. Revogação — ANTES da expiração (evita oracle de timing)
//! 4. Expiração
//! 5. iat futuro — detecta replay attacks
//! 6. Audience
//! 7. Chave — recupera por kid
//! 8. Assinatura híbrida (Ed25519 + ML-DSA)
//! 9. Claims adicionais
//! ```

use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    error::{ZeroTrustError, ZeroTrustResult},
    pqc_engine::{HybridDsaKeyPair, HybridSignature, PqcEngine},
};

// ─── Helpers de tempo ─────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn b64url_encode(data: &[u8]) -> String {
    B64URL.encode(data)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64URL.decode(s)
}

// ─── PQC-JWT ──────────────────────────────────────────────────────────────────

/// Claims de um PQC-JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject
    pub sub:  String,
    /// Issuer
    pub iss:  String,
    /// Audience
    pub aud:  String,
    /// Issued at (UNIX timestamp)
    pub iat:  i64,
    /// Expires at (UNIX timestamp)
    pub exp:  i64,
    /// JWT ID — obrigatório para revogação
    pub jti:  String,
    /// Claims adicionais da aplicação
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    /// Metadados QSEC
    pub qsec: QsecMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsecMeta {
    pub pqc:     bool,
    pub version: u8,
}

/// Gerenciador de PQC-JWT.
///
/// Formato do token: `header.payload.ed25519_sig.mldsa_sig` (4 partes)
///
/// # AVISO DE SEGURANÇA
///
/// `revoked_jtis` é mantido em memória. Em caso de restart do processo,
/// tokens revogados tornam-se válidos novamente.
///
/// **Para produção**: use `load_revoked_jtis()` para restaurar o conjunto
/// persistido e `dump_revoked_jtis()` para salvar após cada revogação.
pub struct PqcJwtManager<'a> {
    engine:        &'a PqcEngine,
    key_registry:  &'a KeyRegistry,
    revoked_jtis:  HashSet<String>,
}

impl<'a> PqcJwtManager<'a> {
    pub fn new(engine: &'a PqcEngine, key_registry: &'a KeyRegistry) -> Self {
        Self {
            engine,
            key_registry,
            revoked_jtis: HashSet::new(),
        }
    }

    /// Emite um PQC-JWT assinado com a chave de assinatura ativa.
    pub fn issue(
        &self,
        subject:   &str,
        extra:     HashMap<String, serde_json::Value>,
        ttl_secs:  i64,
        audience:  &str,
        issuer:    &str,
    ) -> ZeroTrustResult<String> {
        let keypair = self.key_registry.active_signing_key()?;
        let now     = now_secs();
        let jti     = Uuid::new_v4().to_string();

        let header = serde_json::json!({
            "typ": "PQC-JWT",
            "alg": keypair.algorithm,
            "kid": keypair.key_id,
        });

        let claims = JwtClaims {
            sub:   subject.to_string(),
            iss:   issuer.to_string(),
            aud:   audience.to_string(),
            iat:   now,
            exp:   now + ttl_secs,
            jti:   jti.clone(),
            extra,
            qsec:  QsecMeta { pqc: true, version: 3 },
        };

        let h_enc = b64url_encode(
            serde_json::to_string(&header)
                .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?
                .as_bytes()
        );
        let p_enc = b64url_encode(
            serde_json::to_string(&claims)
                .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?
                .as_bytes()
        );

        let signing_input = format!("{h_enc}.{p_enc}");
        let sig = self.engine
            .hybrid_sign(signing_input.as_bytes(), keypair)
            .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?;

        let c_sig_enc = b64url_encode(
            &hex::decode(&sig.classical_sig)
                .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?
        );
        let p_sig_enc = b64url_encode(
            &hex::decode(&sig.pqc_sig)
                .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?
        );

        Ok(format!("{h_enc}.{p_enc}.{c_sig_enc}.{p_sig_enc}"))
    }

    /// Verifica e decodifica um PQC-JWT.
    ///
    /// A ordem de verificação é segura contra timing attacks:
    /// revogação é verificada ANTES da expiração.
    pub fn verify(
        &self,
        token:           &str,
        expected_audience: &str,
        required_claims: Option<&HashMap<String, serde_json::Value>>,
    ) -> ZeroTrustResult<JwtClaims> {
        // 1. Estrutura
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return Err(ZeroTrustError::InvalidTokenFormat { got: parts.len() });
        }
        let (h_enc, p_enc, c_sig_enc, p_sig_enc) = (parts[0], parts[1], parts[2], parts[3]);

        let header_bytes = b64url_decode(h_enc)
            .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?;
        let payload_bytes = b64url_decode(p_enc)
            .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?;
        let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| ZeroTrustError::JwtDecode(e.to_string()))?;

        // 2. Algoritmo — FIRST, antes de qualquer processamento
        let alg = header["alg"].as_str().unwrap_or("").to_string();
        if alg.is_empty()
            || alg.eq_ignore_ascii_case("none")
            || alg.starts_with("RS")
            || alg.starts_with("HS")
            || alg.starts_with("ES")
            || alg.starts_with("PS")
        {
            return Err(ZeroTrustError::InsecureAlgorithm { algorithm: alg });
        }

        // 3. Revogação — ANTES da expiração (evita oracle de timing)
        if claims.jti.is_empty() {
            return Err(ZeroTrustError::MissingClaim { claim: "jti".to_string() });
        }
        if self.revoked_jtis.contains(&claims.jti) {
            return Err(ZeroTrustError::TokenRevoked { jti: claims.jti });
        }

        // 4. Expiração
        let now = now_secs();
        if now > claims.exp {
            return Err(ZeroTrustError::TokenExpired {
                expired_at: chrono::DateTime::from_timestamp(claims.exp, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| claims.exp.to_string()),
            });
        }

        // 5. iat no futuro — replay attack (tolerância de 30s para clock skew)
        if claims.iat > now + 30 {
            return Err(ZeroTrustError::FutureIssuedAt { iat: claims.iat });
        }

        // 6. Audience
        if !expected_audience.is_empty() && claims.aud != expected_audience {
            return Err(ZeroTrustError::AudienceMismatch {
                expected: expected_audience.to_string(),
                actual:   claims.aud.clone(),
            });
        }

        // 7. Chave de verificação
        let kid = header["kid"].as_str().unwrap_or("").to_string();
        let keypair = self.key_registry
            .get_key(&kid)
            .ok_or(ZeroTrustError::UnknownKeyId { kid: kid.clone() })?;

        // 8. Assinatura híbrida
        let signing_input = format!("{h_enc}.{p_enc}");
        let c_sig_bytes = b64url_decode(c_sig_enc)
            .map_err(|_| ZeroTrustError::JwtSignatureInvalid)?;
        let p_sig_bytes = b64url_decode(p_sig_enc)
            .map_err(|_| ZeroTrustError::JwtSignatureInvalid)?;

        let hybrid_sig = HybridSignature {
            version:       3,
            algorithm:     alg,
            key_id:        kid,
            signed_at:     claims.iat,
            message_hash:  hex::encode(<Sha3_256 as Digest>::digest(signing_input.as_bytes())),
            classical_sig: hex::encode(&c_sig_bytes),
            pqc_sig:       hex::encode(&p_sig_bytes),
        };

        let ok = self.engine
            .hybrid_verify(signing_input.as_bytes(), &hybrid_sig, &keypair.public_key)
            .map_err(|_| ZeroTrustError::JwtSignatureInvalid)?;

        if !ok {
            return Err(ZeroTrustError::JwtSignatureInvalid);
        }

        // 9. Claims adicionais
        if let Some(required) = required_claims {
            for (key, expected_val) in required {
                match key.as_str() {
                    "sub" => {
                        if &serde_json::Value::String(claims.sub.clone()) != expected_val {
                            return Err(ZeroTrustError::MissingClaim { claim: key.clone() });
                        }
                    }
                    other => {
                        let actual = claims.extra.get(other);
                        if actual != Some(expected_val) {
                            return Err(ZeroTrustError::MissingClaim { claim: key.clone() });
                        }
                    }
                }
            }
        }

        Ok(claims)
    }

    /// Revoga um token pelo JTI ou pelo token completo.
    pub fn revoke(&mut self, token_or_jti: &str) {
        let jti = if token_or_jti.contains('.') {
            // Extrai JTI do token
            let parts: Vec<&str> = token_or_jti.split('.').collect();
            if parts.len() >= 2 {
                b64url_decode(parts[1]).ok()
                    .and_then(|b| serde_json::from_slice::<JwtClaims>(&b).ok())
                    .map(|c| c.jti)
                    .unwrap_or_else(|| token_or_jti.to_string())
            } else {
                token_or_jti.to_string()
            }
        } else {
            token_or_jti.to_string()
        };
        self.revoked_jtis.insert(jti);
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked_jtis.len()
    }

    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked_jtis.contains(jti)
    }

    /// Exporta JTIs revogados para persistência externa.
    ///
    /// Chame após cada `revoke()` e persista o resultado.
    /// Restaure via `load_revoked_jtis()` ao reiniciar o processo.
    pub fn dump_revoked_jtis(&self) -> Vec<String> {
        self.revoked_jtis.iter().cloned().collect()
    }

    /// Carrega JTIs revogados de armazenamento persistente.
    pub fn load_revoked_jtis(&mut self, jtis: impl IntoIterator<Item = String>) {
        self.revoked_jtis.extend(jtis);
    }
}

// ─── KEY REGISTRY ─────────────────────────────────────────────────────────────

/// Status de uma chave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

/// Entrada no registro de chaves.
pub struct KeyEntry {
    pub keypair:    HybridDsaKeyPair,
    pub status:     KeyStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub rotated_at: Option<i64>,
}

/// Registro de chaves com rotação automática.
///
/// Política Zero Trust:
/// - Toda chave tem TTL obrigatório
/// - Rotação ocorre `rotation_window_secs` antes da expiração
/// - Chaves retired ficam disponíveis para verificação até expirar
/// - Chaves revogadas são removidas imediatamente da verificação
pub struct KeyRegistry {
    engine:               PqcEngine,
    signing_keys:         HashMap<String, KeyEntry>,
    active_signing_kid:   Option<String>,
    signing_ttl_secs:     i64,
    rotation_window_secs: i64,
}

impl KeyRegistry {
    /// Cria registry com TTLs padrão:
    /// - signing: 30 dias
    /// - rotation window: 5 dias antes de expirar
    pub fn new(engine: PqcEngine) -> ZeroTrustResult<Self> {
        let mut registry = Self {
            engine,
            signing_keys:         HashMap::new(),
            active_signing_kid:   None,
            signing_ttl_secs:     86400 * 30,
            rotation_window_secs: 86400 * 5,
        };
        registry.generate_signing_key()?;
        Ok(registry)
    }

    pub fn with_ttl(mut self, signing_ttl_days: u32, rotation_window_days: u32) -> Self {
        self.signing_ttl_secs     = signing_ttl_days as i64 * 86400;
        self.rotation_window_secs = rotation_window_days as i64 * 86400;
        self
    }

    fn generate_signing_key(&mut self) -> ZeroTrustResult<String> {
        let kp  = self.engine.generate_dsa_keypair()
            .map_err(|_| ZeroTrustError::NoActiveKey)?;
        let now = now_secs();
        let kid = kp.key_id.clone();

        self.signing_keys.insert(kid.clone(), KeyEntry {
            keypair:    kp,
            status:     KeyStatus::Active,
            created_at: now,
            expires_at: now + self.signing_ttl_secs,
            rotated_at: None,
        });
        self.active_signing_kid = Some(kid.clone());
        Ok(kid)
    }

    /// Retorna a chave de assinatura ativa, rotacionando se necessário.
    pub fn active_signing_key(&self) -> ZeroTrustResult<&HybridDsaKeyPair> {
        // Note: rotação automática requer &mut self — chamada via rotate_if_needed()
        let kid = self.active_signing_kid.as_deref()
            .ok_or(ZeroTrustError::NoActiveKey)?;
        let entry = self.signing_keys.get(kid)
            .ok_or(ZeroTrustError::NoActiveKey)?;
        if entry.status != KeyStatus::Active {
            return Err(ZeroTrustError::NoActiveKey);
        }
        Ok(&entry.keypair)
    }

    /// Verifica e executa rotação se necessário.
    pub fn rotate_if_needed(&mut self) -> ZeroTrustResult<bool> {
        let now = now_secs();
        let needs_rotation = self.active_signing_kid.as_ref().and_then(|kid| {
            self.signing_keys.get(kid).map(|e| {
                now >= (e.expires_at - self.rotation_window_secs)
            })
        }).unwrap_or(true);

        if needs_rotation {
            // Marca chave atual como retired
            if let Some(kid) = &self.active_signing_kid.clone() {
                if let Some(entry) = self.signing_keys.get_mut(kid) {
                    entry.status     = KeyStatus::Retired;
                    entry.rotated_at = Some(now);
                }
            }
            self.generate_signing_key()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Recupera chave por ID (para verificação de tokens antigos).
    /// Retorna `None` se revogada ou inexistente.
    pub fn get_key(&self, kid: &str) -> Option<&HybridDsaKeyPair> {
        self.signing_keys.get(kid).and_then(|e| {
            if e.status == KeyStatus::Revoked { None } else { Some(&e.keypair) }
        })
    }

    /// Revoga uma chave imediatamente.
    pub fn revoke_key(&mut self, kid: &str) -> ZeroTrustResult<()> {
        let entry = self.signing_keys.get_mut(kid)
            .ok_or(ZeroTrustError::KeyNotFound { kid: kid.to_string() })?;

        entry.status = KeyStatus::Revoked;

        // Se era a chave ativa, gera nova imediatamente
        if self.active_signing_kid.as_deref() == Some(kid) {
            self.active_signing_kid = None;
            self.generate_signing_key()?;
        }

        Ok(())
    }

    /// Relatório de status das chaves.
    pub fn status_report(&self) -> Vec<KeyStatusReport> {
        let now = now_secs();
        self.signing_keys.iter().map(|(kid, e)| {
            KeyStatusReport {
                key_id:            kid.clone(),
                status:            format!("{:?}", e.status),
                algorithm:         e.keypair.algorithm.clone(),
                created_at:        e.created_at,
                expires_at:        e.expires_at,
                days_until_expiry: ((e.expires_at - now) as f64 / 86400.0).max(0.0),
                is_active:         self.active_signing_kid.as_deref() == Some(kid),
            }
        }).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyStatusReport {
    pub key_id:            String,
    pub status:            String,
    pub algorithm:         String,
    pub created_at:        i64,
    pub expires_at:        i64,
    pub days_until_expiry: f64,
    pub is_active:         bool,
}

// ─── API KEY MANAGER ──────────────────────────────────────────────────────────

const API_KEY_PREFIX: &str = "qsec_";
const API_KEY_ENTROPY_BYTES: usize = 32;  // 256 bits

/// Entrada de API key — raw key NUNCA é armazenada.
pub struct ApiKeyEntry {
    pub key_id:     String,
    /// SHA3-256 da raw key — comparação em tempo constante
    key_hash:       Vec<u8>,
    pub name:       String,
    pub scopes:     Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used:  Option<i64>,
    pub revoked:    bool,
}

// SECURITY: Zeroiza o hash no Drop
impl Drop for ApiKeyEntry {
    fn drop(&mut self) {
        self.key_hash.zeroize();
    }
}

/// Gerenciador de API keys com hashing SHA3-256.
///
/// A raw key é exibida UMA ÚNICA VEZ na criação.
/// Somente o hash SHA3-256 é mantido.
/// Comparações usam `subtle::ConstantTimeEq` (tempo constante).
pub struct ApiKeyManager {
    keys: HashMap<String, ApiKeyEntry>,
}

impl ApiKeyManager {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    /// Cria uma API key.
    ///
    /// Retorna `(key_id, raw_key)`.
    /// `raw_key` é exibida **uma única vez** — não pode ser recuperada depois.
    pub fn create(
        &mut self,
        name:     impl Into<String>,
        scopes:   Vec<String>,
        ttl_days: Option<u32>,
    ) -> ZeroTrustResult<(String, String)> {
        use rand_core::RngCore;

        let mut raw_bytes = vec![0u8; API_KEY_ENTROPY_BYTES];
        rand_core::OsRng.fill_bytes(&mut raw_bytes);
        let raw_key = format!("{}{}", API_KEY_PREFIX, hex::encode(&raw_bytes));
        raw_bytes.zeroize();  // Zeroiza os bytes após construir o hex

        let key_hash = <Sha3_256 as Digest>::digest(raw_key.as_bytes()).to_vec();
        let key_id   = format!("kid_{}", Uuid::new_v4().simple());
        let now      = now_secs();

        self.keys.insert(key_id.clone(), ApiKeyEntry {
            key_id:     key_id.clone(),
            key_hash,
            name:       name.into(),
            scopes,
            created_at: now,
            expires_at: ttl_days.map(|d| now + d as i64 * 86400),
            last_used:  None,
            revoked:    false,
        });

        Ok((key_id, raw_key))
    }

    /// Verifica uma API key.
    ///
    /// - Tempo constante via `ConstantTimeEq` — nenhuma informação vaza
    /// - Verifica revogação, expiração e scope
    /// - Atualiza `last_used` se válida
    pub fn verify(
        &mut self,
        raw_key:        &str,
        required_scope: Option<&str>,
    ) -> ZeroTrustResult<&ApiKeyEntry> {
        // Rejeita imediatamente se não tem o prefixo correto
        if !raw_key.starts_with(API_KEY_PREFIX) {
            return Err(ZeroTrustError::InvalidApiKeyFormat);
        }

        let incoming_hash = <Sha3_256 as Digest>::digest(raw_key.as_bytes()).to_vec();
        let now           = now_secs();

        // Itera sobre TODAS as chaves para evitar timing oracle
        // (não para no primeiro match sem verificar o resto)
        let mut matched_kid: Option<String> = None;
        let mut found_match = subtle::Choice::from(0u8);

        for (kid, entry) in &self.keys {
            let hash_match: subtle::Choice = entry.key_hash
                .as_slice()
                .ct_eq(incoming_hash.as_slice());
            if hash_match.into() && matched_kid.is_none() {
                matched_kid = Some(kid.clone());
                found_match = hash_match;
            }
        }

        if !bool::from(found_match) {
            return Err(ZeroTrustError::ApiKeyInvalid);
        }

        let kid   = matched_kid.unwrap();
        let entry = self.keys.get(&kid).unwrap();  // sabemos que existe

        if entry.revoked {
            return Err(ZeroTrustError::ApiKeyRevoked);
        }
        if let Some(exp) = entry.expires_at {
            if now > exp {
                return Err(ZeroTrustError::ApiKeyExpired);
            }
        }
        if let Some(scope) = required_scope {
            if !entry.scopes.iter().any(|s| s == scope) {
                return Err(ZeroTrustError::InsufficientScope {
                    required: scope.to_string(),
                });
            }
        }

        // Atualiza last_used
        self.keys.get_mut(&kid).unwrap().last_used = Some(now);

        Ok(self.keys.get(&kid).unwrap())
    }

    /// Revoga uma API key pelo ID.
    pub fn revoke(&mut self, key_id: &str) -> ZeroTrustResult<()> {
        self.keys.get_mut(key_id)
            .ok_or(ZeroTrustError::ApiKeyInvalid)?
            .revoked = true;
        Ok(())
    }

    /// Lista chaves (sem expor hashes ou material sensível).
    pub fn list(&self) -> Vec<ApiKeyInfo> {
        self.keys.values().map(|e| ApiKeyInfo {
            key_id:     e.key_id.clone(),
            name:       e.name.clone(),
            scopes:     e.scopes.clone(),
            revoked:    e.revoked,
            created_at: e.created_at,
            expires_at: e.expires_at,
            last_used:  e.last_used,
        }).collect()
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self { Self::new() }
}

/// Informações públicas de uma API key (sem o hash).
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub key_id:     String,
    pub name:       String,
    pub scopes:     Vec<String>,
    pub revoked:    bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used:  Option<i64>,
}
