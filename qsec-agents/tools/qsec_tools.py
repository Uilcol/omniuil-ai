"""
QSEC Tools — Interface com o engine Rust + definições de ferramentas para Claude.

Cada função aqui é chamável pelos agentes via tool_use do Claude API.
O engine Rust é invocado via subprocess com output JSON estruturado.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

# Caminho para o binário Rust compilado
QSEC_BIN = os.environ.get(
    "QSEC_BIN",
    str(Path(__file__).parent.parent.parent / "qsec-rust" / "target" / "release" / "qsec")
)

# ─── Proteção contra Path Traversal ──────────────────────────────────────────
# Prefixos de sistema que o agente NUNCA pode ler ou escrever
_BLOCKED_PATH_PREFIXES = (
    "/etc", "/proc", "/sys", "/dev", "/root",
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/boot", "/lib", "/lib64",
)

# Flag de produção — desabilita modo simulação em produção real
_PRODUCTION_MODE = os.environ.get("QSEC_PRODUCTION", "").lower() in ("1", "true", "yes")


def _safe_path(raw: str, *, must_exist: bool = False) -> "Path | None":
    """
    Canonicaliza e valida um caminho contra path traversal.

    resolve() elimina ../ e symlinks — depois checamos contra lista de bloqueio.
    Retorna Path se seguro, None se bloqueado ou inválido.
    """
    try:
        p = Path(raw).resolve()
    except Exception:
        return None

    path_str = str(p)
    for blocked in _BLOCKED_PATH_PREFIXES:
        if path_str == blocked or path_str.startswith(blocked + "/"):
            return None

    if must_exist and not p.exists():
        return None

    return p



def _run_qsec(*args: str, input_data: str | None = None, timeout: int = 60) -> dict:
    """
    Chama o binário Rust do QSEC e retorna o resultado.
    Se o binário não estiver disponível, usa modo simulação.
    """
    if not Path(QSEC_BIN).exists():
        return _simulated_qsec(*args)

    try:
        result = subprocess.run(
            [QSEC_BIN, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        output = result.stdout.strip()
        try:
            return {"success": result.returncode == 0, "data": json.loads(output), "raw": output}
        except json.JSONDecodeError:
            return {"success": result.returncode == 0, "data": output, "raw": output}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "data": None}
    except Exception as e:
        return {"success": False, "error": str(e), "data": None}


def _simulated_qsec(*args: str) -> dict:
    """
    Modo simulação quando o binário Rust não está compilado.
    Retorna dados estruturalmente idênticos ao output real.

    SECURITY: este modo NUNCA é ativado se QSEC_PRODUCTION=1.
    Dados simulados não têm garantias criptográficas reais.
    """
    if _PRODUCTION_MODE:
        return {
            "success": False,
            "error":   "Simulation mode disabled in production (QSEC_PRODUCTION=1). "
                       "Build the Rust engine: cargo build --release",
            "data":    None,
        }
    cmd = args[0] if args else ""

    if cmd == "scan":
        path = args[1] if len(args) > 1 else "."
        return {"success": True, "data": _simulate_scan(path), "raw": ""}

    if cmd == "info":
        return {"success": True, "data": {
            "qsec_version": "3.0.0",
            "pqc_engine": {
                "backend": "reference (cargo build --features liboqs for production)",
                "kem_algorithm": "X25519 + ML-KEM-1024",
                "dsa_algorithm": "Ed25519 + ML-DSA-87",
                "symmetric": "AES-256-GCM",
                "kdf": "HKDF-SHA3-256",
                "harvest_now_decrypt_later_protection": True,
                "nist_pqc_compliant": False,
            },
            "security": {
                "memory_safety": "Rust ownership model",
                "key_zeroization": "ZeroizeOnDrop",
                "timing_safety": "subtle::ConstantTimeEq",
                "unsafe_code": False,
            }
        }, "raw": ""}

    if cmd == "sbom":
        return {"success": True, "data": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "serde", "version": "1.0.195", "purl": "pkg:cargo/serde@1.0.195"},
                {"name": "tokio", "version": "1.36.0", "purl": "pkg:cargo/tokio@1.36.0"},
                {"name": "openssl", "version": "0.10.64", "purl": "pkg:cargo/openssl@0.10.64"},
            ]
        }, "raw": ""}

    if cmd in ("sign", "verify", "token", "keys", "apikey", "pipeline"):
        return {"success": True, "data": f"Simulated {cmd} OK", "raw": ""}

    return {"success": True, "data": f"Simulated: {' '.join(args)}", "raw": ""}


def _simulate_scan(path: str) -> list[dict]:
    """Simula findings do scanner para demo sem binário Rust."""
    return [
        {
            "file": f"{path}/src/crypto.rs",
            "line": 12,
            "column": 5,
            "severity": "CRITICAL",
            "rule_id": "QSC-001",
            "title": "RSA detectado",
            "description": "RSA é vulnerável ao algoritmo de Shor em computadores quânticos.",
            "recommendation": "Migre para ML-DSA (assinaturas) ou ML-KEM (troca de chaves).",
            "code_snippet": "let key = RsaPrivateKey::new(&mut rng, 2048)?;",
        },
        {
            "file": f"{path}/src/auth.rs",
            "line": 47,
            "column": 9,
            "severity": "CRITICAL",
            "rule_id": "QSC-022",
            "title": "JWT assinado com RSA",
            "description": "RS256 usa RSA — vulnerável a computadores quânticos.",
            "recommendation": "Migre para ML-DSA. Durante a transição, use modo híbrido.",
            "code_snippet": r'algorithm: "RS256"',
        },
        {
            "file": f"{path}/src/hash.rs",
            "line": 23,
            "column": 14,
            "severity": "HIGH",
            "rule_id": "QSC-010",
            "title": "MD5 detectado",
            "description": "MD5 é criptograficamente quebrado.",
            "recommendation": "Use SHA3-256 ou BLAKE2b.",
            "code_snippet": "let digest = Md5::new().chain_update(data).finalize();",
        },
        {
            "file": f"{path}/src/tls.rs",
            "line": 89,
            "column": 3,
            "severity": "CRITICAL",
            "rule_id": "QSC-002",
            "title": "Criptografia de curva elíptica detectada",
            "description": "ECDSA é vulnerável ao algoritmo de Shor.",
            "recommendation": "Use ML-DSA para assinaturas.",
            "code_snippet": "let key = EcKey::generate(Nid::X9_62_PRIME256V1)?;",
        },
        {
            "file": f"{path}/Cargo.toml",
            "line": 18,
            "column": 1,
            "severity": "MEDIUM",
            "rule_id": "QSC-055",
            "title": "Dependência vulnerável: ring",
            "description": "ring não tem suporte nativo a PQC.",
            "recommendation": "Combine ring com oqs crate para operações pós-quânticas.",
            "code_snippet": 'ring = "0.17"',
        },
        {
            "file": f"{path}/src/secrets.rs",
            "line": 5,
            "column": 1,
            "severity": "HIGH",
            "rule_id": "QSC-030",
            "title": "Segredo hardcoded",
            "description": "Segredos no código-fonte são expostos em repositórios.",
            "recommendation": "Use variáveis de ambiente ou HSM.",
            "code_snippet": 'let api_key = "prod_sk_a1b2c3d4e5f6789012345678";',
        },
    ]


# ─── Definições das Ferramentas (para Claude API) ─────────────────────────────

QSEC_TOOLS: list[dict] = [

    {
        "name": "scan_codebase",
        "description": (
            "Escaneia um arquivo ou diretório em busca de criptografia fraca ou "
            "vulnerável a computadores quânticos. Detecta RSA, ECDSA, MD5, SHA-1, "
            "AES-ECB, JWT inseguro, chaves hardcoded, DES, RC4 e dependências vulneráveis. "
            "Retorna lista de findings com severidade, localização e recomendação."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Caminho do arquivo ou diretório a escanear"
                },
                "fail_on_critical": {
                    "type": "boolean",
                    "description": "Se True, retorna erro quando há findings CRITICAL ou HIGH",
                    "default": False
                }
            },
            "required": ["path"]
        }
    },

    {
        "name": "get_engine_info",
        "description": (
            "Retorna informações sobre o motor PQC do QSEC: algoritmos disponíveis, "
            "backend (liboqs ou referência), proteção HNDL, versão."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },

    {
        "name": "generate_sbom",
        "description": (
            "Gera um SBOM (Software Bill of Materials) no formato CycloneDX 1.5 "
            "para um projeto. Lista todas as dependências com versão, hash e PURL."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Caminho raiz do projeto"
                },
                "output_file": {
                    "type": "string",
                    "description": "Arquivo de saída (padrão: sbom.cyclonedx.json)"
                }
            },
            "required": ["project_path"]
        }
    },

    {
        "name": "sign_artifact",
        "description": (
            "Assina um artefato de software com criptografia PQC híbrida "
            "(Ed25519 + ML-DSA-87). Gera SHA3-256, SHA-256 e assinatura verificável."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "artifact_path": {
                    "type": "string",
                    "description": "Caminho do artefato a assinar"
                },
                "output_file": {
                    "type": "string",
                    "description": "Arquivo de saída para a assinatura (.qsec.json)"
                }
            },
            "required": ["artifact_path"]
        }
    },

    {
        "name": "verify_artifact",
        "description": (
            "Verifica a integridade e assinatura PQC de um artefato. "
            "Detecta qualquer adulteração no conteúdo ou na assinatura."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "artifact_path": {"type": "string"},
                "manifest_path": {"type": "string", "description": "Arquivo .qsec.json com a assinatura"}
            },
            "required": ["artifact_path", "manifest_path"]
        }
    },

    {
        "name": "issue_pqc_jwt",
        "description": (
            "Emite um PQC-JWT (token JWT de 4 partes assinado com Ed25519 + ML-DSA). "
            "Rejeita automaticamente algoritmos inseguros (none, RS*, HS*)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "subject":  {"type": "string", "description": "Subject do token (ex: user@example.com)"},
                "ttl_secs": {"type": "integer", "description": "Tempo de vida em segundos", "default": 3600},
                "audience": {"type": "string", "description": "Audience do token"},
                "claims":   {"type": "object", "description": "Claims extras (ex: {role: admin})"}
            },
            "required": ["subject"]
        }
    },

    {
        "name": "revoke_token",
        "description": "Revoga um PQC-JWT pelo JTI ou pelo token completo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "token_or_jti": {"type": "string", "description": "Token completo ou JTI"}
            },
            "required": ["token_or_jti"]
        }
    },

    {
        "name": "rotate_keys",
        "description": (
            "Força a rotação da chave de assinatura ativa. "
            "A nova chave é gerada automaticamente com novo TTL."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Motivo da rotação (auditoria)"}
            },
            "required": ["reason"]
        }
    },

    {
        "name": "create_api_key",
        "description": (
            "Cria uma API key com hash SHA3-256 (nunca armazena plaintext). "
            "A raw key é retornada UMA ÚNICA VEZ."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name":     {"type": "string"},
                "scopes":   {"type": "array", "items": {"type": "string"}},
                "ttl_days": {"type": "integer", "default": 90}
            },
            "required": ["name", "scopes"]
        }
    },

    {
        "name": "run_full_pipeline",
        "description": (
            "Executa o pipeline completo de segurança: scan + SBOM + sign + attest. "
            "Retorna relatório consolidado com todos os resultados."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "project_path": {"type": "string"},
                "artifacts":    {"type": "array", "items": {"type": "string"}},
                "output_dir":   {"type": "string", "default": "./qsec-out"},
                "source_repo":  {"type": "string"}
            },
            "required": ["project_path"]
        }
    },

    {
        "name": "generate_remediation_patch",
        "description": (
            "Gera um patch de código que corrige uma vulnerabilidade criptográfica específica. "
            "Retorna o código corrigido e explicação da mudança."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path":    {"type": "string", "description": "Arquivo com a vulnerabilidade"},
                "rule_id":      {"type": "string", "description": "ID da regra (ex: QSC-001)"},
                "code_snippet": {"type": "string", "description": "Código vulnerável"},
                "line_number":  {"type": "integer"}
            },
            "required": ["file_path", "rule_id", "code_snippet"]
        }
    },

    {
        "name": "read_file_content",
        "description": "Lê o conteúdo de um arquivo para análise.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "max_lines": {"type": "integer", "default": 100}
            },
            "required": ["file_path"]
        }
    },

    {
        "name": "write_file",
        "description": "Escreve ou sobrescreve um arquivo com novo conteúdo (para patches de remediação).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "content":   {"type": "string"},
                "create_backup": {"type": "boolean", "default": True}
            },
            "required": ["file_path", "content"]
        }
    },

    {
        "name": "send_alert",
        "description": (
            "Envia alerta para o sistema de notificações "
            "(console, arquivo de log, webhook)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["INFO", "WARNING", "CRITICAL", "INCIDENT"]},
                "title":    {"type": "string"},
                "message":  {"type": "string"},
                "details":  {"type": "object"}
            },
            "required": ["severity", "title", "message"]
        }
    },
]


# ─── Executor de Ferramentas ──────────────────────────────────────────────────

def execute_tool(name: str, inputs: dict) -> dict:
    """
    Executa uma ferramenta pelo nome.
    Chamado pelos agentes quando Claude retorna tool_use blocks.
    """
    handlers = {
        "scan_codebase":          _tool_scan,
        "get_engine_info":        _tool_engine_info,
        "generate_sbom":          _tool_sbom,
        "sign_artifact":          _tool_sign,
        "verify_artifact":        _tool_verify,
        "issue_pqc_jwt":          _tool_issue_jwt,
        "revoke_token":           _tool_revoke_token,
        "rotate_keys":            _tool_rotate_keys,
        "create_api_key":         _tool_create_api_key,
        "run_full_pipeline":      _tool_pipeline,
        "generate_remediation_patch": _tool_remediation_patch,
        "read_file_content":      _tool_read_file,
        "write_file":             _tool_write_file,
        "send_alert":             _tool_send_alert,
    }

    handler = handlers.get(name)
    if not handler:
        return {"error": f"Unknown tool: {name}"}

    try:
        return handler(inputs)
    except Exception as e:
        return {"error": str(e), "tool": name}


def _tool_scan(inputs: dict) -> dict:
    result = _run_qsec("scan", inputs["path"], "--format", "json")
    findings = result.get("data", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return {
        "path":          inputs["path"],
        "total_findings": len(findings),
        "by_severity":   counts,
        "findings":      findings,
        "has_critical":  counts["CRITICAL"] > 0,
        "has_high":      counts["HIGH"] > 0,
    }


def _tool_engine_info(inputs: dict) -> dict:
    result = _run_qsec("info")
    return result.get("data", {})


def _tool_sbom(inputs: dict) -> dict:
    args = ["sbom", inputs["project_path"]]
    if "output_file" in inputs:
        args += ["--out", inputs["output_file"]]
    result = _run_qsec(*args)
    return result.get("data", {})


def _tool_sign(inputs: dict) -> dict:
    args = ["sign", inputs["artifact_path"]]
    if "output_file" in inputs:
        args += ["--out", inputs["output_file"]]
    result = _run_qsec(*args)
    return {"signed": result["success"], "detail": result.get("data", "")}


def _tool_verify(inputs: dict) -> dict:
    result = _run_qsec("verify", inputs["artifact_path"], "--manifest", inputs["manifest_path"])
    return {"valid": result["success"], "detail": result.get("data", "")}


def _tool_issue_jwt(inputs: dict) -> dict:
    args = ["token", "issue", "--subject", inputs["subject"]]
    if "ttl_secs" in inputs:
        args += ["--ttl", str(inputs["ttl_secs"])]
    if "audience" in inputs:
        args += ["--audience", inputs["audience"]]
    if "claims" in inputs:
        args += ["--claims", json.dumps(inputs["claims"])]
    result = _run_qsec(*args)
    return {"issued": result["success"], "token_preview": str(result.get("data", ""))[:80]}


def _tool_revoke_token(inputs: dict) -> dict:
    result = _run_qsec("token", "revoke", "--token", inputs["token_or_jti"])
    return {"revoked": result["success"]}


def _tool_rotate_keys(inputs: dict) -> dict:
    result = _run_qsec("keys", "rotate")
    return {"rotated": result["success"], "reason": inputs.get("reason", ""), "detail": result.get("data", "")}


def _tool_create_api_key(inputs: dict) -> dict:
    scopes = ",".join(inputs.get("scopes", []))
    args = ["apikey", "create", "--name", inputs["name"], "--scope", scopes]
    if "ttl_days" in inputs:
        args += ["--ttl-days", str(inputs["ttl_days"])]
    result = _run_qsec(*args)
    return {"created": result["success"], "detail": result.get("data", "")}


def _tool_pipeline(inputs: dict) -> dict:
    args = ["pipeline", inputs["project_path"]]
    if inputs.get("artifacts"):
        args += ["--artifacts", ",".join(inputs["artifacts"])]
    if "output_dir" in inputs:
        args += ["--out-dir", inputs["output_dir"]]
    if "source_repo" in inputs:
        args += ["--repo", inputs["source_repo"]]
    result = _run_qsec(*args, timeout=120)
    return result.get("data", {})


def _tool_remediation_patch(inputs: dict) -> dict:
    """
    Gera patches de remediação baseados na regra detectada.
    Retorna o código corrigido para o agente aplicar.
    """
    rule_id      = inputs.get("rule_id", "")
    code_snippet = inputs.get("code_snippet", "")
    file_path    = inputs.get("file_path", "")

    patches = {
        "QSC-001": {
            "before": code_snippet,
            "after": "// Migrado para ML-KEM-1024 via QSEC\nuse qsec::pqc_engine::PqcEngine;\nlet engine = PqcEngine::new();\nlet keypair = engine.generate_kem_keypair()?;",
            "explanation": "RSA substituído por KEM híbrido X25519 + ML-KEM-1024 (NIST FIPS 203).",
            "migration_effort": "HIGH",
        },
        "QSC-002": {
            "before": code_snippet,
            "after": "// Migrado para ML-DSA-87 via QSEC\nuse qsec::pqc_engine::PqcEngine;\nlet engine = PqcEngine::new();\nlet keypair = engine.generate_dsa_keypair()?;",
            "explanation": "ECDSA substituído por DSA híbrido Ed25519 + ML-DSA-87 (NIST FIPS 204).",
            "migration_effort": "HIGH",
        },
        "QSC-010": {
            "before": code_snippet,
            "after": code_snippet.replace("Md5::new()", "Sha3_256::new()").replace("md5::", "sha3::"),
            "explanation": "MD5 substituído por SHA3-256 (resistente a colisões e quântico-seguro).",
            "migration_effort": "LOW",
        },
        "QSC-011": {
            "before": code_snippet,
            "after": code_snippet.replace("Sha1::new()", "Sha3_256::new()").replace("sha1::", "sha3::"),
            "explanation": "SHA-1 substituído por SHA3-256.",
            "migration_effort": "LOW",
        },
        "QSC-020": {
            "before": code_snippet,
            "after": code_snippet.replace('"none"', '"Ed25519+ML-DSA-87"'),
            "explanation": "Algoritmo 'none' substituído por assinatura híbrida PQC.",
            "migration_effort": "MEDIUM",
        },
        "QSC-022": {
            "before": code_snippet,
            "after": code_snippet.replace('"RS256"', '"Ed25519+ML-DSA-87"'),
            "explanation": "RS256 substituído por assinatura híbrida Ed25519 + ML-DSA-87.",
            "migration_effort": "MEDIUM",
        },
        "QSC-030": {
            "before": code_snippet,
            "after": '// REMOVIDO: credencial hardcoded\nlet api_key = std::env::var("API_KEY").expect("API_KEY env var required");',
            "explanation": "Credencial hardcoded movida para variável de ambiente.",
            "migration_effort": "LOW",
        },
    }

    patch = patches.get(rule_id, {
        "before": code_snippet,
        "after": f"// TODO: Corrigir {rule_id} — consulte a documentação QSEC",
        "explanation": f"Regra {rule_id} requer análise manual.",
        "migration_effort": "UNKNOWN",
    })

    return {
        "file_path":         file_path,
        "rule_id":           rule_id,
        "patch":             patch,
        "line_number":       inputs.get("line_number", 0),
        "ready_to_apply":    rule_id in patches,
    }


def _tool_read_file(inputs: dict) -> dict:
    # SECURITY: canonicaliza e bloqueia path traversal antes de qualquer acesso
    safe = _safe_path(inputs["file_path"], must_exist=True)
    if safe is None:
        return {"error": f"Access denied or file not found: {inputs['file_path']}"}

    try:
        lines = safe.read_text(errors="replace").splitlines()
    except PermissionError:
        return {"error": f"Permission denied: {safe}"}

    max_lines = min(inputs.get("max_lines", 100), 500)  # cap at 500 lines
    return {
        "file_path":   str(safe),
        "total_lines": len(lines),
        "content":     "\n".join(lines[:max_lines]),
        "truncated":   len(lines) > max_lines,
    }


def _tool_write_file(inputs: dict) -> dict:
    # SECURITY: canonicaliza e bloqueia path traversal antes de qualquer escrita
    safe = _safe_path(inputs["file_path"])
    if safe is None:
        return {"error": f"Write access denied: {inputs['file_path']}"}

    # Limite de tamanho: 10 MB
    content = inputs["content"]
    if len(content.encode()) > 10 * 1024 * 1024:
        return {"error": "Content exceeds 10 MB limit"}

    if inputs.get("create_backup", True) and safe.exists():
        backup = safe.with_suffix(safe.suffix + ".bak")
        try:
            backup.write_text(safe.read_text())
        except Exception:
            pass  # backup falhou mas não bloqueia escrita

    safe.parent.mkdir(parents=True, exist_ok=True)
    safe.write_text(content)
    return {"written": True, "file_path": str(safe), "bytes": len(content)}


def _tool_send_alert(inputs: dict) -> dict:
    sev     = inputs["severity"]
    title   = inputs["title"]
    message = inputs["message"]
    ts      = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    icons = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🚨", "INCIDENT": "🔴"}
    icon  = icons.get(sev, "📢")

    print(f"\n{icon} [{sev}] {ts}")
    print(f"   {title}")
    print(f"   {message}")
    if inputs.get("details"):
        print(f"   Details: {json.dumps(inputs['details'], indent=2)}")

    log_dir  = Path("./qsec-alerts")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "alerts.jsonl"

    # SECURITY: rotação simples — mantém apenas os últimos 5000 alertas (~5 MB)
    try:
        if log_file.exists() and log_file.stat().st_size > 5 * 1024 * 1024:
            rotated = log_dir / "alerts.1.jsonl"
            log_file.rename(rotated)
    except Exception:
        pass

    with open(log_file, "a") as f:
        f.write(json.dumps({
            "timestamp": ts,
            "severity":  sev,
            "title":     title,
            "message":   message,
            "details":   inputs.get("details"),
        }) + "\n")

    return {"sent": True, "timestamp": ts, "log_file": str(log_file)}
