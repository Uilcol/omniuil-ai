//! # Adaptadores de Linguagem — Absorção do OmniUil AI
//!
//! Regras específicas por linguagem para detectar APIs criptográficas
//! que o scanner de padrões genéricos pode perder.
//!
//! ## Linguagens suportadas
//!
//! | Linguagem      | Extensões                     | APIs específicas detectadas         |
//! |----------------|-------------------------------|-------------------------------------|
//! | Rust           | `.rs`                         | RustCrypto, ring, openssl bindings  |
//! | Python         | `.py`                         | PyCryptodome, cryptography, hashlib |
//! | Java           | `.java`                       | JCE, Bouncy Castle, JSSE            |
//! | C#             | `.cs`                         | System.Security.Cryptography        |
//! | Go             | `.go`                         | crypto/rsa, crypto/md5, x/crypto    |
//! | JavaScript     | `.js`, `.jsx`                 | crypto module, node-forge, jose     |
//! | TypeScript     | `.ts`, `.tsx`                 | mesmas do JavaScript                |
//!
//! ## Separação de responsabilidades
//!
//! Este módulo **não importa** `scanner.rs` para evitar dependência circular.
//! O scanner importa este módulo e converte `LanguageMatch` → `CryptoFinding`.

use lazy_static::lazy_static;
use regex::Regex;

// ─── Linguagem detectada ──────────────────────────────────────────────────────

/// Linguagem de programação detectada por extensão de arquivo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    Python,
    Java,
    CSharp,
    Go,
    JavaScript,
    TypeScript,
    Kotlin,
    Swift,
    Ruby,
    Cpp,
    C,
    Unknown,
}

impl Language {
    /// Retorna o nome da linguagem como string (para filtro YAML).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rust       => "rust",
            Self::Python     => "python",
            Self::Java       => "java",
            Self::CSharp     => "csharp",
            Self::Go         => "go",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Kotlin     => "kotlin",
            Self::Swift      => "swift",
            Self::Ruby       => "ruby",
            Self::Cpp        => "cpp",
            Self::C          => "c",
            Self::Unknown    => "unknown",
        }
    }
}

/// Detecta a linguagem de programação pelo caminho/extensão do arquivo.
pub fn detect_language(path: &std::path::Path) -> Language {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Nomes de arquivo especiais
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "rs"                   => Language::Rust,
        "py" | "pyw" | "pyi"  => Language::Python,
        "java"                 => Language::Java,
        "cs"                   => Language::CSharp,
        "go"                   => Language::Go,
        "js" | "jsx" | "mjs" | "cjs"  => Language::JavaScript,
        "ts" | "tsx"           => Language::TypeScript,
        "kt" | "kts"           => Language::Kotlin,
        "swift"                => Language::Swift,
        "rb" | "rake"          => Language::Ruby,
        "cpp" | "cc" | "cxx" | "hxx" | "hpp" => Language::Cpp,
        "c" | "h"              => Language::C,
        _ => {
            // Casos especiais por nome de arquivo
            if name == "cargo.toml" || name == "cargo.lock" {
                Language::Rust
            } else if name == "requirements.txt" || name == "pyproject.toml" {
                Language::Python
            } else if name == "go.mod" || name == "go.sum" {
                Language::Go
            } else {
                Language::Unknown
            }
        }
    }
}

// ─── Match de regra de linguagem ─────────────────────────────────────────────

/// Match retornado pelos adaptadores de linguagem.
/// Sem dependência em `scanner::CryptoFinding`.
#[derive(Debug, Clone)]
pub struct LanguageMatch {
    pub rule_id:        &'static str,
    pub severity_str:   &'static str,
    pub title:          &'static str,
    pub description:    &'static str,
    pub recommendation: &'static str,
    pub column:         usize,
    pub matched_text:   String,
}

// ─── Regra de linguagem compilada ────────────────────────────────────────────

struct LangRule {
    id:             &'static str,
    severity:       &'static str,
    title:          &'static str,
    description:    &'static str,
    recommendation: &'static str,
    pattern:        Regex,
}

// ─── Regras por linguagem (compiladas uma vez) ────────────────────────────────

lazy_static! {

    // ── Python ────────────────────────────────────────────────────────────────
    static ref PYTHON_RULES: Vec<LangRule> = vec![
        LangRule {
            id: "QSC-PY-001", severity: "CRITICAL",
            title: "RSA via PyCryptodome detectado",
            description: "Crypto.PublicKey.RSA usa RSA clássico, vulnerável ao algoritmo de Shor.",
            recommendation: "Use ML-DSA (assinaturas) ou ML-KEM (encapsulamento) via liboqs.",
            pattern: Regex::new(r"(?i)from\s+Crypto\.PublicKey\s+import\s+RSA|Crypto\.PublicKey\.RSA\b|RSA\.generate\s*\(|rsa\.newkeys\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-PY-002", severity: "CRITICAL",
            title: "ECDSA/ECC via PyCryptodome detectado",
            description: "Crypto.PublicKey.ECC usa curvas elípticas, vulnerável ao algoritmo de Shor.",
            recommendation: "Use ML-DSA para assinaturas pós-quânticas.",
            pattern: Regex::new(r"(?i)from\s+Crypto\.PublicKey\s+import\s+ECC|Crypto\.PublicKey\.ECC\b|ecdsa\.SigningKey\.generate\s*\(|ecdsa\.NIST\w+Curve").unwrap(),
        },
        LangRule {
            id: "QSC-PY-003", severity: "HIGH",
            title: "hashlib.md5 detectado",
            description: "MD5 está criptograficamente quebrado desde 2004.",
            recommendation: "Use hashlib.sha3_256() ou hashlib.blake2b().",
            pattern: Regex::new(r"hashlib\.md5\s*\(|hmac\.new\s*\([^,]+,\s*[^,]+,\s*hashlib\.md5").unwrap(),
        },
        LangRule {
            id: "QSC-PY-004", severity: "HIGH",
            title: "hashlib.sha1 detectado",
            description: "SHA-1 está oficialmente quebrado (SHAttered, 2017).",
            recommendation: "Use hashlib.sha3_256().",
            pattern: Regex::new(r"hashlib\.sha1\s*\(|hmac\.new\s*\([^,]+,\s*[^,]+,\s*hashlib\.sha1").unwrap(),
        },
        LangRule {
            id: "QSC-PY-005", severity: "HIGH",
            title: "DES via PyCryptodome detectado",
            description: "DES tem chave de 56 bits — quebrado por força bruta. 3DES foi depreciado pelo NIST em 2023.",
            recommendation: "Use AES-256-GCM via Crypto.Cipher.AES com MODE_GCM.",
            pattern: Regex::new(r"(?i)from\s+Crypto\.Cipher\s+import\s+(?:DES|DES3)|Crypto\.Cipher\.DES\b|DES3\.new\s*\(|DES\.new\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-PY-006", severity: "CRITICAL",
            title: "ARC4/RC4 via PyCryptodome detectado",
            description: "RC4 tem múltiplas vulnerabilidades, proibido no TLS (RFC 7465).",
            recommendation: "Use ChaCha20-Poly1305 ou AES-256-GCM.",
            pattern: Regex::new(r"(?i)from\s+Crypto\.Cipher\s+import\s+ARC4|ARC4\.new\s*\(|arc4\.ARC4\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-PY-007", severity: "HIGH",
            title: "AES em modo ECB (Python) detectado",
            description: "AES-ECB não é semanticamente seguro — padrões no plaintext vazam para o ciphertext.",
            recommendation: "Use AES.MODE_GCM (autenticado) ou ChaCha20-Poly1305.",
            pattern: Regex::new(r"AES\.new\s*\([^,]+,\s*AES\.MODE_ECB|MODE_ECB").unwrap(),
        },
        LangRule {
            id: "QSC-PY-008", severity: "MEDIUM",
            title: "SSL sem verificação de certificado (Python)",
            description: "ssl.create_default_context() com check_hostname=False ou verify_mode=CERT_NONE desabilita verificação TLS.",
            recommendation: "Mantenha a verificação de certificado habilitada. Use certifi para certificados atualizados.",
            pattern: Regex::new(r"check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE|SSLContext\s*\(ssl\.PROTOCOL_TLS\)").unwrap(),
        },
    ];

    // ── Java ──────────────────────────────────────────────────────────────────
    static ref JAVA_RULES: Vec<LangRule> = vec![
        LangRule {
            id: "QSC-JV-001", severity: "CRITICAL",
            title: "RSA via JCE detectado",
            description: "KeyPairGenerator.getInstance(\"RSA\") usa RSA clássico — vulnerável ao algoritmo de Shor.",
            recommendation: "Use implementação PQC com Bouncy Castle + CRYSTALS-Dilithium/Kyber.",
            pattern: Regex::new(r#"KeyPairGenerator\.getInstance\s*\(\s*"RSA"|KeyFactory\.getInstance\s*\(\s*"RSA"|RSAPublicKeySpec\b|RSAPrivateKeySpec\b|new\s+RSACipher\s*\("#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-002", severity: "CRITICAL",
            title: "ECDSA/EC via JCE detectado",
            description: "Curvas elípticas (ECDSA, ECDH) são vulneráveis ao algoritmo de Shor.",
            recommendation: "Migre para ML-DSA via Bouncy Castle PQC.",
            pattern: Regex::new(r#"KeyPairGenerator\.getInstance\s*\(\s*"EC"|KeyAgreement\.getInstance\s*\(\s*"ECDH"|Signature\.getInstance\s*\(\s*"SHA\d+withECDSA|ECPoint\b|ECPublicKeySpec\b"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-003", severity: "HIGH",
            title: "MD5 via JCE detectado",
            description: "MessageDigest.getInstance(\"MD5\") usa MD5 quebrado.",
            recommendation: "Use MessageDigest.getInstance(\"SHA3-256\").",
            pattern: Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"MD5"|DigestUtils\.md5\b|Md5Crypt\b"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-004", severity: "HIGH",
            title: "SHA-1 via JCE detectado",
            description: "SHA-1 está oficialmente quebrado. NIST desaprovou em 2011.",
            recommendation: "Use MessageDigest.getInstance(\"SHA3-256\").",
            pattern: Regex::new(r#"MessageDigest\.getInstance\s*\(\s*"SHA-?1"|DigestUtils\.sha1\b|DigestUtils\.sha\b"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-005", severity: "HIGH",
            title: "DES/3DES via JCE detectado",
            description: "Cipher.getInstance(\"DES\") ou TripleDES — depreciados pelo NIST em 2023.",
            recommendation: "Use Cipher.getInstance(\"AES/GCM/NoPadding\") com chave de 256 bits.",
            pattern: Regex::new(r#"Cipher\.getInstance\s*\(\s*"(?:DES|DESede|3DES)(?:/[^"]+)?"|SecretKeyFactory\.getInstance\s*\(\s*"DES|KeyGenerator\.getInstance\s*\(\s*"DES"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-006", severity: "HIGH",
            title: "AES/ECB via JCE detectado",
            description: "Cipher.getInstance(\"AES/ECB\") usa modo ECB — semanticamente inseguro.",
            recommendation: "Use Cipher.getInstance(\"AES/GCM/NoPadding\") com GCMParameterSpec.",
            pattern: Regex::new(r#"Cipher\.getInstance\s*\(\s*"AES(?:/ECB|/PKCS5Padding)?"\s*\)"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-007", severity: "MEDIUM",
            title: "Diffie-Hellman clássico (Java) detectado",
            description: "KeyPairGenerator.getInstance(\"DH\") usa DH clássico — vulnerável ao Shor.",
            recommendation: "Use ML-KEM para troca de chaves pós-quântica.",
            pattern: Regex::new(r#"KeyPairGenerator\.getInstance\s*\(\s*"DH"|KeyAgreement\.getInstance\s*\(\s*"DiffieHellman"#).unwrap(),
        },
        LangRule {
            id: "QSC-JV-008", severity: "MEDIUM",
            title: "TLS sem configuração explícita (Java)",
            description: "SSLContext.getInstance(\"SSL\") ou \"TLS\" sem especificação pode usar TLS 1.0/1.1.",
            recommendation: "Use SSLContext.getInstance(\"TLSv1.3\") e configure ciphersuites explicitamente.",
            pattern: Regex::new(r#"SSLContext\.getInstance\s*\(\s*"(?:SSL|TLS|TLSv1|TLSv1\.1|TLSv1\.2)"\s*\)"#).unwrap(),
        },
    ];

    // ── C# ────────────────────────────────────────────────────────────────────
    static ref CSHARP_RULES: Vec<LangRule> = vec![
        LangRule {
            id: "QSC-CS-001", severity: "CRITICAL",
            title: "RSACryptoServiceProvider detectado",
            description: "RSACryptoServiceProvider usa RSA clássico — vulnerável ao algoritmo de Shor.",
            recommendation: "Aguarde suporte PQC nativo no .NET 10+ ou use BouncyCastle com ML-DSA.",
            pattern: Regex::new(r"(?i)new\s+RSACryptoServiceProvider\s*\(|RSA\.Create\s*\(\s*\d+|RSACng\b").unwrap(),
        },
        LangRule {
            id: "QSC-CS-002", severity: "CRITICAL",
            title: "ECDsa/ECDiffieHellman (C#) detectado",
            description: "Curvas elípticas são vulneráveis ao algoritmo de Shor.",
            recommendation: "Migre para ML-DSA/ML-KEM quando disponível no .NET.",
            pattern: Regex::new(r"(?i)ECDsa\.Create\s*\(|ECDsaCng\b|ECDiffieHellman\.Create\s*\(|ECDiffieHellmanCng\b|new\s+ECDsaOpenSsl\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-CS-003", severity: "HIGH",
            title: "MD5CryptoServiceProvider (C#) detectado",
            description: "MD5 está criptograficamente quebrado.",
            recommendation: "Use SHA3-256: var h = SHA3_256.HashData(data); (disponível no .NET 8+).",
            pattern: Regex::new(r"(?i)new\s+MD5CryptoServiceProvider\s*\(|MD5\.Create\s*\(\s*\)|MD5\b\.ComputeHash").unwrap(),
        },
        LangRule {
            id: "QSC-CS-004", severity: "HIGH",
            title: "SHA1CryptoServiceProvider (C#) detectado",
            description: "SHA-1 está oficialmente quebrado.",
            recommendation: "Use SHA256.HashData() ou SHA3_256.HashData() (.NET 8+).",
            pattern: Regex::new(r"(?i)new\s+SHA1CryptoServiceProvider\s*\(|SHA1\.Create\s*\(\s*\)|SHA1Managed\b|SHA1\b\.ComputeHash").unwrap(),
        },
        LangRule {
            id: "QSC-CS-005", severity: "HIGH",
            title: "DESCryptoServiceProvider / TripleDES (C#) detectado",
            description: "DES (56-bit) e 3DES foram depreciados pelo NIST em 2023.",
            recommendation: "Use AesGcm com chave de 256 bits.",
            pattern: Regex::new(r"(?i)new\s+DESCryptoServiceProvider\s*\(|new\s+TripleDESCryptoServiceProvider\s*\(|DES\.Create\s*\(|TripleDES\.Create\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-CS-006", severity: "HIGH",
            title: "RijndaelManaged (AES-ECB implícito) detectado",
            description: "RijndaelManaged usa modo ECB por padrão — semanticamente inseguro.",
            recommendation: "Use AesGcm (autenticado) disponível no System.Security.Cryptography.",
            pattern: Regex::new(r"(?i)new\s+RijndaelManaged\s*\(|RijndaelManaged\b").unwrap(),
        },
        LangRule {
            id: "QSC-CS-007", severity: "HIGH",
            title: "AesCryptoServiceProvider sem modo GCM (C#)",
            description: "AesCryptoServiceProvider com CipherMode.ECB ou CBC não é autenticado.",
            recommendation: "Use AesGcm ou AesCcm para criptografia autenticada.",
            pattern: Regex::new(r"(?i)CipherMode\.ECB|CipherMode\.CBC|new\s+AesCryptoServiceProvider\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-CS-008", severity: "MEDIUM",
            title: "Random usado para criptografia (C#)",
            description: "System.Random não é criptograficamente seguro.",
            recommendation: "Use RandomNumberGenerator.GetBytes() para geração de bytes aleatórios seguros.",
            pattern: Regex::new(r"(?i)new\s+Random\s*\(\s*\)\s*\.Next|new\s+System\.Random\s*\(").unwrap(),
        },
    ];

    // ── Go ────────────────────────────────────────────────────────────────────
    static ref GO_RULES: Vec<LangRule> = vec![
        LangRule {
            id: "QSC-GO-001", severity: "CRITICAL",
            title: "crypto/rsa detectado (Go)",
            description: "rsa.GenerateKey usa RSA clássico — vulnerável ao algoritmo de Shor.",
            recommendation: "Use circl (github.com/cloudflare/circl) com ML-KEM/ML-DSA.",
            pattern: Regex::new(r#"rsa\.GenerateKey\s*\(|rsa\.EncryptPKCS1v15\s*\(|rsa\.SignPKCS1v15\s*\(|"crypto/rsa""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-002", severity: "CRITICAL",
            title: "crypto/ecdsa ou crypto/elliptic detectado (Go)",
            description: "ecdsa.GenerateKey usa curvas elípticas — vulnerável ao algoritmo de Shor.",
            recommendation: "Use circl com ML-DSA para assinaturas pós-quânticas.",
            pattern: Regex::new(r#"ecdsa\.GenerateKey\s*\(|elliptic\.P256\s*\(\)|elliptic\.P384\s*\(\)|elliptic\.P521\s*\(\)|"crypto/ecdsa"|"crypto/elliptic""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-003", severity: "HIGH",
            title: "crypto/md5 detectado (Go)",
            description: "md5.Sum() e md5.New() usam MD5 quebrado.",
            recommendation: "Use crypto/sha256 com sha256.Sum256() ou golang.org/x/crypto/sha3.",
            pattern: Regex::new(r#"md5\.Sum\s*\(|md5\.New\s*\(\s*\)|"crypto/md5""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-004", severity: "HIGH",
            title: "crypto/sha1 detectado (Go)",
            description: "sha1.Sum() e sha1.New() usam SHA-1 quebrado.",
            recommendation: "Use golang.org/x/crypto/sha3 com sha3.Sum256().",
            pattern: Regex::new(r#"sha1\.Sum\s*\(|sha1\.New\s*\(\s*\)|"crypto/sha1""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-005", severity: "HIGH",
            title: "crypto/des detectado (Go)",
            description: "des.NewCipher() usa DES (56-bit) — quebrado por força bruta.",
            recommendation: "Use crypto/aes com cipher.NewGCM() e chave de 32 bytes (AES-256).",
            pattern: Regex::new(r#"des\.NewCipher\s*\(|des\.NewTripleDESCipher\s*\(|"crypto/des""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-006", severity: "HIGH",
            title: "crypto/rc4 detectado (Go)",
            description: "rc4.NewCipher() usa RC4 — múltiplas vulnerabilidades, proibido no TLS.",
            recommendation: "Use golang.org/x/crypto/chacha20poly1305.",
            pattern: Regex::new(r#"rc4\.NewCipher\s*\(|"crypto/rc4""#).unwrap(),
        },
        LangRule {
            id: "QSC-GO-007", severity: "HIGH",
            title: "AES-ECB ou AES-CBC sem autenticação (Go)",
            description: "cipher.NewCBCEncrypter sem autenticação permite ataques de padding oracle.",
            recommendation: "Use cipher.NewGCM() (autenticado) ou golang.org/x/crypto/chacha20poly1305.",
            pattern: Regex::new(r"cipher\.NewCBCEncrypter\s*\(|cipher\.NewCBCDecrypter\s*\(|cipher\.NewECBEncrypter\s*\(").unwrap(),
        },
        LangRule {
            id: "QSC-GO-008", severity: "MEDIUM",
            title: "math/rand usado para criptografia (Go)",
            description: "math/rand não é criptograficamente seguro.",
            recommendation: "Use crypto/rand.Read() para geração de bytes aleatórios seguros.",
            pattern: Regex::new(r#"rand\.Seed\s*\(|rand\.Int\s*\(\)|rand\.Intn\s*\(|"math/rand""#).unwrap(),
        },
    ];

    // ── JavaScript / TypeScript ───────────────────────────────────────────────
    static ref JS_RULES: Vec<LangRule> = vec![
        LangRule {
            id: "QSC-JS-001", severity: "HIGH",
            title: "crypto.createHash MD5/SHA1 (Node.js) detectado",
            description: "createHash('md5') e createHash('sha1') usam algoritmos quebrados.",
            recommendation: "Use crypto.createHash('sha3-256') ou crypto.createHash('sha256').",
            pattern: Regex::new(r#"crypto\.createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\)"#).unwrap(),
        },
        LangRule {
            id: "QSC-JS-002", severity: "CRITICAL",
            title: "crypto.createSign RSA/ECDSA (Node.js) detectado",
            description: "Uso de RSA ou ECDSA para assinaturas digitais — vulnerável ao Shor.",
            recommendation: "Considere migração futura para ML-DSA quando bibliotecas JS maduras estiverem disponíveis.",
            pattern: Regex::new(r#"crypto\.createSign\s*\(\s*['"](?:RSA-SHA\d+|SHA\d+withRSA|ECDSA)['"]\s*\)"#).unwrap(),
        },
        LangRule {
            id: "QSC-JS-003", severity: "CRITICAL",
            title: "jwt.sign com algoritmo RS*/HS* (Node.js)",
            description: "jsonwebtoken.sign com RS256/HS256 usa algoritmos clássicos vulneráveis.",
            recommendation: "Use EdDSA como mínimo imediato. Migre para ML-DSA a médio prazo.",
            pattern: Regex::new(r#"(?:jwt|jsonwebtoken)\.sign\s*\([^)]*(?:algorithm\s*:\s*['"](?:RS|HS|ES)\d+|,\s*['"](?:RS|HS|ES)\d+['"])"#).unwrap(),
        },
        LangRule {
            id: "QSC-JS-004", severity: "HIGH",
            title: "Math.random() para criptografia (JavaScript)",
            description: "Math.random() não é criptograficamente seguro.",
            recommendation: "Use crypto.getRandomValues() no browser ou crypto.randomBytes() no Node.js.",
            pattern: Regex::new(r"Math\.random\s*\(\s*\)").unwrap(),
        },
        LangRule {
            id: "QSC-JS-005", severity: "MEDIUM",
            title: "node-forge RSA detectado",
            description: "forge.pki.rsa.generateKeyPair usa RSA clássico.",
            recommendation: "Substitua por implementação híbrida com ML-KEM quando disponível.",
            pattern: Regex::new(r"forge\.pki\.rsa\.generateKeyPair\s*\(|forge\.pki\.createCertificate\s*\(").unwrap(),
        },
    ];

} // fim de lazy_static!

// ─── Função pública ───────────────────────────────────────────────────────────

/// Retorna as regras específicas para a linguagem detectada.
///
/// Retorna slice vazio para linguagens sem regras específicas (não causa erro).
pub fn get_extra_patterns(lang: &Language) -> &'static [LangRule] {
    match lang {
        Language::Python     => &PYTHON_RULES,
        Language::Java       => &JAVA_RULES,
        Language::CSharp     => &CSHARP_RULES,
        Language::Go         => &GO_RULES,
        Language::JavaScript
        | Language::TypeScript => &JS_RULES,
        // Rust, Kotlin, Swift, Ruby, C/C++, Unknown:
        // as regras globais em scanner.rs já cobrem estes casos
        _ => &[],
    }
}

/// Aplica as regras de linguagem a uma linha de código.
///
/// Retorna todos os matches (pode ser vazio).
pub fn apply_language_rules(lang: &Language, line: &str) -> Vec<LanguageMatch> {
    let rules = get_extra_patterns(lang);
    let mut matches = Vec::new();

    for rule in rules {
        if let Some(m) = rule.pattern.find(line) {
            matches.push(LanguageMatch {
                rule_id:        rule.id,
                severity_str:   rule.severity,
                title:          rule.title,
                description:    rule.description,
                recommendation: rule.recommendation,
                column:         m.start() + 1,
                matched_text:   m.as_str().to_string(),
            });
        }
    }

    matches
}

// ─── Testes ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_language() {
        let tests = vec![
            ("main.rs",         Language::Rust),
            ("app.py",          Language::Python),
            ("Main.java",       Language::Java),
            ("Program.cs",      Language::CSharp),
            ("main.go",         Language::Go),
            ("index.js",        Language::JavaScript),
            ("app.ts",          Language::TypeScript),
            ("index.tsx",       Language::TypeScript),
            ("Cargo.toml",      Language::Rust),
            ("requirements.txt",Language::Python),
            ("unknown.xyz",     Language::Unknown),
        ];

        for (filename, expected) in tests {
            let path = std::path::Path::new(filename);
            assert_eq!(
                detect_language(path), expected,
                "Falhou para: {}", filename
            );
        }
    }

    #[test]
    fn test_python_md5() {
        let matches = apply_language_rules(
            &Language::Python,
            "h = hashlib.md5(data.encode())",
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-PY-003");
    }

    #[test]
    fn test_java_rsa_keygen() {
        let matches = apply_language_rules(
            &Language::Java,
            r#"KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");"#,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-JV-001");
        assert_eq!(matches[0].severity_str, "CRITICAL");
    }

    #[test]
    fn test_csharp_rsa() {
        let matches = apply_language_rules(
            &Language::CSharp,
            "var rsa = new RSACryptoServiceProvider(2048);",
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-CS-001");
    }

    #[test]
    fn test_go_md5() {
        let matches = apply_language_rules(
            &Language::Go,
            r#"h := md5.Sum(data)"#,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-GO-003");
    }

    #[test]
    fn test_go_import_md5() {
        let matches = apply_language_rules(
            &Language::Go,
            r#"import "crypto/md5""#,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-GO-003");
    }

    #[test]
    fn test_js_createhash_sha1() {
        let matches = apply_language_rules(
            &Language::JavaScript,
            r#"const h = crypto.createHash('sha1').update(data).digest('hex');"#,
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-JS-001");
    }

    #[test]
    fn test_typescript_same_as_js() {
        // TypeScript usa as mesmas regras que JavaScript
        let matches_ts = apply_language_rules(
            &Language::TypeScript,
            "const h = crypto.createHash('md5').update(data);",
        );
        let matches_js = apply_language_rules(
            &Language::JavaScript,
            "const h = crypto.createHash('md5').update(data);",
        );
        assert_eq!(matches_ts.len(), matches_js.len());
    }

    #[test]
    fn test_unknown_language_no_rules() {
        let matches = apply_language_rules(
            &Language::Unknown,
            "anything",
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn test_csharp_rijndael() {
        let matches = apply_language_rules(
            &Language::CSharp,
            "var aes = new RijndaelManaged();",
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "QSC-CS-006");
    }

    #[test]
    fn test_java_aes_ecb() {
        let matches = apply_language_rules(
            &Language::Java,
            r#"Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");"#,
        );
        assert!(!matches.is_empty(), "AES/ECB deve ser detectado em Java");
    }
}
