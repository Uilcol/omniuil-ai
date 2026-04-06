//! # QSEC CLI
//!
//! Interface de linha de comando da plataforma QSEC v3.
//!
//! ```
//! USAGE:
//!   qsec scan    <path> [--format text|json|sarif] [--fail-on-critical] [--config .qsec.toml]
//!   qsec sign    <artifact> [--out <manifest.json>]
//!   qsec verify  <artifact> --manifest <manifest.json>
//!   qsec sbom    <project>  [--out <sbom.json>]
//!   qsec keys    status | rotate | revoke --key-id <kid>
//!   qsec token   issue --subject <sub> [--ttl 3600] [--audience <aud>]
//!   qsec token   verify --token <jwt> [--audience <aud>]
//!   qsec apikey  create --name <n> --scope read,write [--ttl-days 90]
//!   qsec apikey  verify --key <raw> [--scope <s>]
//!   qsec pipeline <project> [--artifacts a,b] [--out-dir ./qsec-out]
//!   qsec config  init          → gera .qsec.toml de exemplo
//!   qsec info
//! ```

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process,
};

use clap::{Parser, Subcommand, Args, ValueEnum};
use serde_json::json;
use toml;

use qsec::{QsecConfig, QsecPlatform, VERSION};

// ─── CLI RAIZ ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "qsec",
    version = VERSION,
    about   = "Post-Quantum Cryptographic Firewall for Software",
    long_about = "QSEC v3 — Infraestrutura de Confiança Criptográfica para a Era Quântica\n\
                  Detecta crypto fraca, assina artefatos com PQC híbrido,\n\
                  gera SBOM CycloneDX 1.5, emite PQC-JWT e exporta SARIF 2.1.0.",
    propagate_version = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Nível de verbosidade
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Caminho do arquivo de configuração .qsec.toml (auto-detectado se não especificado)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Escaneia código-fonte em busca de criptografia fraca
    Scan(ScanArgs),

    /// Assina um artefato com criptografia PQC híbrida
    Sign(SignArgs),

    /// Verifica a assinatura de um artefato
    Verify(VerifyArgs),

    /// Gera SBOM (Software Bill of Materials) CycloneDX 1.5
    Sbom(SbomArgs),

    /// Gerencia chaves criptográficas
    Keys(KeysArgs),

    /// Gerencia PQC-JWT
    Token(TokenArgs),

    /// Gerencia API Keys
    Apikey(ApikeyArgs),

    /// Executa o pipeline de segurança completo (scan + sbom + sign + attest)
    Pipeline(PipelineArgs),

    /// Gerencia configuração enterprise (.qsec.toml)
    Config(ConfigArgs),

    /// Exibe informações da plataforma
    Info,
}

// ─── SCAN ─────────────────────────────────────────────────────────────────────

#[derive(Args)]
struct ScanArgs {
    /// Caminho do arquivo ou diretório a escanear
    path: PathBuf,

    /// Formato de saída
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Retorna exit code 1 se houver findings CRITICAL ou HIGH
    #[arg(long)]
    fail_on_critical: bool,

    /// Ignora severidades abaixo deste nível na saída
    #[arg(long, value_enum)]
    min_severity: Option<MinSeverity>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    /// SARIF 2.1.0 — upload direto para GitHub Security tab
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum MinSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Args)]
struct SignArgs {
    /// Arquivo a assinar
    artifact: PathBuf,

    /// Arquivo de saída (padrão: artifact.qsec.json)
    #[arg(long)]
    out: Option<PathBuf>,
}

// ─── VERIFY ───────────────────────────────────────────────────────────────────

#[derive(Args)]
struct VerifyArgs {
    /// Artefato a verificar
    artifact: PathBuf,

    /// Arquivo de manifest com a assinatura
    #[arg(long)]
    manifest: PathBuf,
}

// ─── SBOM ─────────────────────────────────────────────────────────────────────

#[derive(Args)]
struct SbomArgs {
    /// Diretório raiz do projeto
    project: PathBuf,

    /// Arquivo de saída (padrão: sbom.cyclonedx.json)
    #[arg(long, default_value = "sbom.cyclonedx.json")]
    out: PathBuf,
}

// ─── KEYS ─────────────────────────────────────────────────────────────────────

#[derive(Args)]
struct KeysArgs {
    #[command(subcommand)]
    action: KeysAction,
}

#[derive(Subcommand)]
enum KeysAction {
    /// Exibe status de todas as chaves
    Status,
    /// Força rotação da chave ativa
    Rotate,
    /// Revoga uma chave por ID
    Revoke {
        /// ID da chave a revogar
        #[arg(long)]
        key_id: String,
    },
}

// ─── TOKEN ────────────────────────────────────────────────────────────────────

#[derive(Args)]
struct TokenArgs {
    #[command(subcommand)]
    action: TokenAction,
}

#[derive(Subcommand)]
enum TokenAction {
    /// Emite um novo PQC-JWT
    Issue {
        /// Subject do token (ex: user@example.com)
        #[arg(long)]
        subject: String,

        /// Tempo de vida em segundos (padrão: 3600)
        #[arg(long, default_value = "3600")]
        ttl: i64,

        /// Audience do token
        #[arg(long, default_value = "")]
        audience: String,

        /// Claims extras em JSON (ex: '{"role":"admin"}')
        #[arg(long, default_value = "{}")]
        claims: String,
    },

    /// Verifica e decodifica um PQC-JWT
    Verify {
        /// Token a verificar
        #[arg(long)]
        token: String,

        /// Audience esperada
        #[arg(long, default_value = "")]
        audience: String,
    },
}

// ─── APIKEY ───────────────────────────────────────────────────────────────────

#[derive(Args)]
struct ApikeyArgs {
    #[command(subcommand)]
    action: ApikeyAction,
}

#[derive(Subcommand)]
enum ApikeyAction {
    /// Cria uma nova API key
    Create {
        /// Nome da API key
        #[arg(long)]
        name: String,

        /// Escopos separados por vírgula (ex: read,write,admin)
        #[arg(long)]
        scope: String,

        /// TTL em dias (padrão: 90, 0 = sem expiração)
        #[arg(long, default_value = "90")]
        ttl_days: u32,
    },

    /// Verifica uma API key
    Verify {
        /// Raw key a verificar
        #[arg(long)]
        key: String,

        /// Escopo requerido
        #[arg(long)]
        scope: Option<String>,
    },

    /// Revoga uma API key
    Revoke {
        /// ID da key a revogar
        #[arg(long)]
        key_id: String,
    },

    /// Lista todas as API keys
    List,
}

// ─── PIPELINE ─────────────────────────────────────────────────────────────────

#[derive(Args)]
struct PipelineArgs {
    /// Diretório raiz do projeto
    project: PathBuf,

    /// Artefatos a assinar (separados por vírgula)
    #[arg(long, value_delimiter = ',')]
    artifacts: Vec<PathBuf>,

    /// Diretório de saída para os relatórios
    #[arg(long, default_value = "./qsec-out")]
    out_dir: PathBuf,

    /// URL do repositório fonte
    #[arg(long)]
    repo: Option<String>,
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match run(cli) {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("\n❌ Error: {e}");
            process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    // Carrega config enterprise — do path explícito ou auto-detectado
    let config = if let Some(config_path) = &cli.config {
        match std::fs::read_to_string(config_path) {
            Ok(content) => toml::from_str::<QsecConfig>(&content).unwrap_or_default(),
            Err(e) => {
                eprintln!("[QSEC] Warning: could not read config {}: {e}", config_path.display());
                QsecConfig::default()
            }
        }
    } else {
        let scan_path = match &cli.command {
            Command::Scan(a)     => a.path.parent().unwrap_or(&a.path).to_path_buf(),
            Command::Pipeline(a) => a.project.clone(),
            _                    => std::env::current_dir().unwrap_or_default(),
        };
        QsecConfig::load_from_dir(&scan_path)
    };

    match cli.command {
        Command::Scan(args)     => cmd_scan(args, &config),
        Command::Sign(args)     => cmd_sign(args),
        Command::Verify(args)   => cmd_verify(args),
        Command::Sbom(args)     => cmd_sbom(args),
        Command::Keys(args)     => cmd_keys(args),
        Command::Token(args)    => cmd_token(args),
        Command::Apikey(args)   => cmd_apikey(args),
        Command::Pipeline(args) => cmd_pipeline(args),
        Command::Config(args)   => cmd_config(args),
        Command::Info           => cmd_info(),
    }
}

// ─── Comandos ─────────────────────────────────────────────────────────────────

fn cmd_scan(args: ScanArgs, config: &QsecConfig) -> Result<i32, Box<dyn std::error::Error>> {
    let mut platform = QsecPlatform::new()?;

    // Usa scan com config — respeita ignore_paths, disabled_rules, custom_patterns
    platform.scanner.clear();
    if args.path.is_file() {
        platform.scanner.scan_file_with_config(&args.path, Some(config))?;
    } else {
        platform.scanner.scan_directory_with_config(&args.path, Some(config))?;
    }

    // Filtra por min_severity se especificado
    let findings = if let Some(min) = &args.min_severity {
        let min_ord = match min {
            MinSeverity::Critical => 3,
            MinSeverity::High     => 2,
            MinSeverity::Medium   => 1,
            MinSeverity::Low      => 0,
        };
        platform.scanner.findings.iter().filter(|f| {
            let ord = match f.severity {
                qsec::scanner::Severity::Critical => 3,
                qsec::scanner::Severity::High     => 2,
                qsec::scanner::Severity::Medium   => 1,
                qsec::scanner::Severity::Low      => 0,
            };
            ord >= min_ord
        }).cloned().collect::<Vec<_>>()
    } else {
        platform.scanner.findings.clone()
    };

    match args.format {
        OutputFormat::Text  => println!("{}", platform.scan_report_text()),
        OutputFormat::Json  => println!("{}", serde_json::to_string_pretty(&findings)?),
        OutputFormat::Sarif => {
            let sarif_log = qsec::sarif::findings_to_sarif(&findings);
            println!("{}", qsec::sarif::to_json(&sarif_log)?);
        }
    }

    // Determina falha com base na config ou --fail-on-critical
    let should_fail = if args.fail_on_critical {
        platform.scanner.has_blocking_findings()
    } else {
        findings.iter().any(|f| config.should_fail(&f.severity.to_string()))
    };

    if should_fail {
        eprintln!("\n⚠️  Blocking findings detected. See findings above. Failing build.");
        return Ok(1);
    }
    Ok(0)
}

fn cmd_sign(args: SignArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let platform = QsecPlatform::new()?;
    let sign_kp  = platform.key_registry.active_signing_key()?;
    let signer   = qsec::ArtifactSigner::new(&platform.engine, sign_kp);

    let sa  = signer.sign(&args.artifact, None)?;
    let out = args.out.unwrap_or_else(|| {
        args.artifact.with_extension("qsec.json")
    });

    let json = serde_json::to_string_pretty(&sa)?;
    std::fs::write(&out, &json)?;

    println!("✅ Signed: {}", args.artifact.display());
    println!("   SHA3-256 : {}", sa.sha3_256);
    println!("   Key ID   : {}", sa.key_id);
    println!("   Algorithm: {}", sa.algorithm);
    println!("   Output   : {}", out.display());
    Ok(0)
}

fn cmd_verify(args: VerifyArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let manifest_bytes = std::fs::read(&args.manifest)?;
    let sa: qsec::SignedArtifact = serde_json::from_slice(&manifest_bytes)?;

    let platform = QsecPlatform::new()?;
    let sign_kp  = platform.key_registry.active_signing_key()?;
    let signer   = qsec::ArtifactSigner::new(&platform.engine, sign_kp);

    match signer.verify(&args.artifact, &sa) {
        Ok(()) => {
            println!("✅ {} — integrity verified", args.artifact.display());
            println!("   SHA3-256 : {}", sa.sha3_256);
            println!("   Algorithm: {}", sa.algorithm);
            println!("   Signed at: {}", sa.signed_at);
            Ok(0)
        }
        Err(e) => {
            eprintln!("❌ Verification FAILED: {e}");
            Ok(1)
        }
    }
}

fn cmd_sbom(args: SbomArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let platform = QsecPlatform::new()?;
    let sbom     = platform.generate_sbom(&args.project)?;
    let json     = sbom.to_json()?;
    std::fs::write(&args.out, &json)?;

    println!("✅ SBOM generated: {}", args.out.display());
    println!("   Components : {}", sbom.components.len());
    println!("   Format     : CycloneDX {}", sbom.spec_version);
    println!("   Serial     : {}", sbom.serial_number);
    Ok(0)
}

fn cmd_keys(args: KeysArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let mut platform = QsecPlatform::new()?;

    match args.action {
        KeysAction::Status => {
            let report = platform.key_registry.status_report();
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        KeysAction::Rotate => {
            let rotated = platform.key_registry.rotate_if_needed()?;
            if rotated {
                println!("✅ Key rotated successfully");
                println!("{}", serde_json::to_string_pretty(&platform.key_registry.status_report())?);
            } else {
                println!("ℹ️  No rotation needed — key is within valid window");
            }
        }
        KeysAction::Revoke { key_id } => {
            platform.key_registry.revoke_key(&key_id)?;
            println!("✅ Key revoked: {key_id}");
            println!("   A new signing key has been generated automatically.");
        }
    }
    Ok(0)
}

fn cmd_token(args: TokenArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let mut platform = QsecPlatform::new()?;

    match args.action {
        TokenAction::Issue { subject, ttl, audience, claims } => {
            let extra: HashMap<String, serde_json::Value> = serde_json::from_str(&claims)
                .map_err(|e| format!("Invalid --claims JSON: {e}"))?;

            platform.key_registry.rotate_if_needed()?;
            let token = platform.jwt_issue(&subject, extra, ttl, &audience)?;
            let parts = token.split('.').count();

            println!("✅ PQC-JWT issued:");
            println!("   Subject  : {subject}");
            println!("   TTL      : {ttl}s");
            println!("   Audience : {}", if audience.is_empty() { "(none)" } else { &audience });
            println!("   Parts    : {parts} (header.payload.ed25519_sig.mldsa_sig)");
            println!("   Token    : {}...", &token[..token.len().min(72)]);
            println!();
            println!("{token}");
        }
        TokenAction::Verify { token, audience } => {
            match platform.jwt_verify(&token, &audience) {
                Ok(claims) => {
                    println!("✅ Token valid:");
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "sub": claims.sub,
                        "iss": claims.iss,
                        "aud": claims.aud,
                        "iat": claims.iat,
                        "exp": claims.exp,
                        "jti": claims.jti,
                        "extra": claims.extra,
                        "qsec": claims.qsec,
                    }))?);
                }
                Err(e) => {
                    eprintln!("❌ Token invalid: {e}");
                    return Ok(1);
                }
            }
        }
    }
    Ok(0)
}

fn cmd_apikey(args: ApikeyArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let mut platform = QsecPlatform::new()?;

    match args.action {
        ApikeyAction::Create { name, scope, ttl_days } => {
            let scopes: Vec<String> = scope.split(',')
                .map(|s| s.trim().to_string())
                .collect();
            let ttl = if ttl_days == 0 { None } else { Some(ttl_days) };
            let (key_id, raw_key) = platform.api_key_create(&name, scopes.clone(), ttl)?;

            println!("✅ API Key created:");
            println!("   Key ID   : {key_id}");
            println!("   Name     : {name}");
            println!("   Scopes   : {}", scopes.join(", "));
            println!("   TTL      : {} days", ttl_days);
            println!();
            println!("⚠️  Raw key (displayed ONCE — store securely):");
            println!("   {raw_key}");
        }
        ApikeyAction::Verify { key, scope } => {
            match platform.api_key_verify(&key, scope.as_deref()) {
                Ok(kid) => {
                    println!("✅ API key valid");
                    println!("   Key ID: {kid}");
                }
                Err(e) => {
                    eprintln!("❌ API key invalid: {e}");
                    return Ok(1);
                }
            }
        }
        ApikeyAction::Revoke { key_id } => {
            platform.api_keys.revoke(&key_id)?;
            println!("✅ API key revoked: {key_id}");
        }
        ApikeyAction::List => {
            let keys = platform.api_keys.list();
            println!("{}", serde_json::to_string_pretty(&keys)?);
        }
    }
    Ok(0)
}

fn cmd_pipeline(args: PipelineArgs) -> Result<i32, Box<dyn std::error::Error>> {
    let mut platform  = QsecPlatform::new()?;
    let art_refs: Vec<&Path> = args.artifacts.iter().map(PathBuf::as_path).collect();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║      QSEC v{VERSION} — Security Pipeline                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  Project : {}", args.project.display());
    println!("  Output  : {}", args.out_dir.display());
    println!();

    let report = platform.full_pipeline(
        &args.project,
        &art_refs,
        &args.out_dir,
        args.repo.as_deref(),
    )?;

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Pipeline Summary                                            ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Scan      : {} findings ({} CRITICAL)", report.scan_findings, report.scan_critical);
    println!("║  SBOM      : {} components", report.sbom_components);
    println!("║  Signed    : {} artifacts", report.artifacts_signed);
    println!("║  Attest    : {} subjects", report.attestation_subjects);
    println!("╚══════════════════════════════════════════════════════════════╝");

    if report.scan_critical > 0 {
        eprintln!("\n⚠️  {} CRITICAL crypto findings — review required", report.scan_critical);
        return Ok(1);
    }
    Ok(0)
}

fn cmd_info() -> Result<i32, Box<dyn std::error::Error>> {
    let platform = QsecPlatform::new()?;
    let info     = platform.engine_info();
    let keys     = platform.key_registry.status_report();

    println!("{}", serde_json::to_string_pretty(&json!({
        "qsec_version":   VERSION,
        "pqc_engine":     info,
        "keys":           keys,
        "security": {
            "memory_safety":     "Rust ownership model — no GC, no use-after-free",
            "key_zeroization":   "ZeroizeOnDrop on all private key material",
            "timing_safety":     "subtle::ConstantTimeEq on all secret comparisons",
            "unsafe_code":       false,
        }
    }))?);
    Ok(0)
}

// ─── Config Command ───────────────────────────────────────────────────────────

#[derive(Args)]
struct ConfigArgs {
    #[command(subcommand)]
    action: ConfigAction,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Gera um .qsec.toml de exemplo com todas as opções documentadas
    Init {
        /// Sobrescreve se já existir
        #[arg(long)]
        force: bool,
    },
    /// Valida o .qsec.toml existente
    Validate {
        /// Caminho do config (padrão: .qsec.toml)
        #[arg(long, default_value = ".qsec.toml")]
        path: PathBuf,
    },
    /// Exibe a config ativa (após merge de defaults + arquivo)
    Show {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

fn cmd_config(args: ConfigArgs) -> Result<i32, Box<dyn std::error::Error>> {
    match args.action {
        ConfigAction::Init { force } => {
            let path = std::path::Path::new(".qsec.toml");
            if path.exists() && !force {
                eprintln!(".qsec.toml already exists. Use --force to overwrite.");
                return Ok(1);
            }
            std::fs::write(path, QsecConfig::example_toml())?;
            println!("✅ .qsec.toml created");
            println!("   Edit it to customize rules, integrations and thresholds.");
            println!("   Env vars are expanded with ${{VAR_NAME}} syntax.");
        }
        ConfigAction::Validate { path } => {
            let content = std::fs::read_to_string(&path)?;
            match toml::from_str::<QsecConfig>(&content) {
                Ok(_)  => println!("✅ {} is valid", path.display()),
                Err(e) => {
                    eprintln!("❌ Config error in {}: {e}", path.display());
                    return Ok(1);
                }
            }
        }
        ConfigAction::Show { dir } => {
            let config = QsecConfig::load_from_dir(&dir);
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
    }
    Ok(0)
}
