"""
OmniUil AI — Sistema de Licenciamento Comercial
Licença: Comercial — github.com/Uilcol/omniuil-ai
"""
from __future__ import annotations
import json, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from jose import jwt, JWTError

EVALUATION_DAYS   = 90
LICENSE_DIR       = Path.home() / ".omniuil"
LICENSE_STATE_FILE= LICENSE_DIR / "install_state.json"

OMNIUIL_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsg5U31BiVAMiYNV+cK1Ybd6SRWX79K2sTdVu0VnEkME=
-----END PUBLIC KEY-----"""

TIER_LIMITS = {
    "starter": {
        "repos": 5, "agents": ["scanner","analysis"],
        "users": 1, "api_rate_limit": 30,
        "auto_remediate": False, "integrations": False,
        "compliance_report": False,
    },
    "pro": {
        "repos": None, "agents": ["scanner","analysis","remediation","monitoring","incident"],
        "users": 5, "api_rate_limit": 300,
        "auto_remediate": True, "integrations": True,
        "compliance_report": True,
    },
    "enterprise": {
        "repos": None, "agents": ["scanner","analysis","remediation","monitoring","incident"],
        "users": None, "api_rate_limit": None,
        "auto_remediate": True, "integrations": True,
        "compliance_report": True,
    },
}

def _load_state() -> dict:
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    if LICENSE_STATE_FILE.exists():
        try:
            return json.loads(LICENSE_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    state = {
        "install_id": str(uuid.uuid4()),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "company_size_declared": None,
        "license_key": None,
    }
    LICENSE_STATE_FILE.write_text(json.dumps(state, indent=2))
    return state

def _save_state(state: dict) -> None:
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    LICENSE_STATE_FILE.write_text(json.dumps(state, indent=2))

def declare_company_size(size_bucket: str) -> dict:
    state = _load_state()
    state["company_size_declared"] = size_bucket
    _save_state(state)
    return state

def days_since_install() -> int:
    state = _load_state()
    installed = datetime.fromisoformat(state["installed_at"])
    return (datetime.now(timezone.utc) - installed).days

def is_small_company() -> bool:
    state = _load_state()
    return state.get("company_size_declared") == "1-9"

def has_valid_license_key() -> bool:
    state = _load_state()
    key = state.get("license_key")
    if not key:
        return False
    try:
        payload = jwt.decode(key, OMNIUIL_PUBLIC_KEY, algorithms=["EdDSA"])
        return payload.get("exp", 0) > time.time()
    except JWTError:
        return False

def install_license_key(license_key: str) -> tuple[bool, str]:
    try:
        payload = jwt.decode(license_key, OMNIUIL_PUBLIC_KEY, algorithms=["EdDSA"])
    except JWTError as e:
        return False, f"Chave de licença inválida: {e}"
    exp = payload.get("exp", 0)
    if exp <= time.time():
        return False, "Esta chave de licença expirou."
    state = _load_state()
    state["license_key"]   = license_key
    state["licensed_to"]   = payload.get("company", "desconhecido")
    _save_state(state)
    valid_until = datetime.fromtimestamp(exp, tz=timezone.utc)
    return True, f"Licença ativada para {payload.get('company')}. Válida até {valid_until.date()}."

def check_access() -> dict:
    days   = days_since_install()
    small  = is_small_company()
    licensed = has_valid_license_key()
    if small:
        return {"access": "full", "reason": "empresa_pequena_isenta"}
    if licensed:
        return {"access": "full", "reason": "licenca_valida"}
    if days <= EVALUATION_DAYS:
        return {
            "access": "full", "reason": "periodo_avaliacao",
            "days_remaining": EVALUATION_DAYS - days,
        }
    return {
        "access": "limited", "reason": "avaliacao_expirada",
        "message": (
            f"Período de avaliação de {EVALUATION_DAYS} dias encerrado. "
            "Solicite uma licença comercial: github.com/Uilcol/omniuil-ai"
        ),
    }

def get_tier() -> str:
    state = _load_state()
    key = state.get("license_key")
    if not key:
        return "free"
    try:
        payload = jwt.decode(key, OMNIUIL_PUBLIC_KEY, algorithms=["EdDSA"])
        return payload.get("tier", "starter")
    except JWTError:
        return "free"

def get_tier_limits() -> dict:
    tier = get_tier()
    if tier == "free":
        return {
            "repos": 0, "agents": [], "users": 0,
            "api_rate_limit": 0, "auto_remediate": False,
            "integrations": False, "compliance_report": False,
        }
    return TIER_LIMITS.get(tier, TIER_LIMITS["starter"])

def check_repo_limit(current_repos: int) -> tuple[bool, str]:
    limits   = get_tier_limits()
    max_repos = limits.get("repos")
    if max_repos is None:
        return True, "ok"
    if current_repos >= max_repos:
        tier = get_tier()
        return False, f"Limite de {max_repos} repositório(s) atingido no plano {tier.upper()}."
    return True, "ok"

def issue_license_key(
    company: str,
    months: int,
    private_key_pem: str,
    tier: str = "starter"
) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=30 * months)
    payload = {
        "company":   company,
        "tier":      tier,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "exp":       exp.timestamp(),
    }
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA")
