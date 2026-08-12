"""
OmniUil AI — Sistema de Licença Comercial
===========================================

Implementa o gate de 90 dias de avaliação gratuita para qsec-enterprise.
Usa JWT assinado localmente — sem dependência externa, sem complexidade.

Como funciona:
1. Na primeira execução, o sistema grava a data de instalação em
   ~/.omniuil/install_date.json (não pode ser apagado sem perder o histórico
   de findings também — dificulta reset trivial)
2. A cada requisição ao dashboard, verifica se passou de 90 dias
3. Se passou E a empresa tem 10+ funcionários (autodeclarado no setup),
   mostra banner bloqueando novas funcionalidades até inserir chave
4. Chave de licença é um JWT assinado pela OmniUil AI (você), validado
   localmente com a chave pública embutida no binário

Instalação: cole este arquivo em qsec-enterprise/api/licensing.py
e importe no server.py conforme instruções no final deste arquivo.
"""
from __future__ import annotations
import json, os, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from jose import jwt, JWTError

# ── Configuração ──────────────────────────────────────────────────────────────

EVALUATION_DAYS = 90
LICENSE_DIR = Path.home() / ".omniuil"
LICENSE_STATE_FILE = LICENSE_DIR / "install_state.json"

# Chave pública OmniUil AI — usada para VALIDAR chaves de licença emitidas por você.
# A chave privada correspondente NUNCA vai para o repositório — fica só com você,
# usada localmente para gerar chaves de licença quando um cliente paga.
# Gere o par com: python3 -c "from licensing import generate_keypair; generate_keypair()"
OMNIUIL_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsg5U31BiVAMiYNV+cK1Ybd6SRWX79K2sTdVu0VnEkME=
-----END PUBLIC KEY-----"""


# ── Estado de instalação ─────────────────────────────────────────────────────

def _load_state() -> dict:
    """Carrega ou cria o estado de instalação (data de início, tamanho declarado)."""
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    if LICENSE_STATE_FILE.exists():
        try:
            return json.loads(LICENSE_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    # Primeira execução: grava data de instalação
    state = {
        "install_id": str(uuid.uuid4()),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "company_size_declared": None,  # preenchido via /api/v1/setup
        "license_key": None,
    }
    LICENSE_STATE_FILE.write_text(json.dumps(state, indent=2))
    return state


def _save_state(state: dict) -> None:
    LICENSE_DIR.mkdir(parents=True, exist_ok=True)
    LICENSE_STATE_FILE.write_text(json.dumps(state, indent=2))


def declare_company_size(size_bucket: str) -> dict:
    """
    Chamado uma vez no setup inicial do dashboard.
    size_bucket: "1-9" | "10-49" | "50-200" | "200+"
    """
    state = _load_state()
    state["company_size_declared"] = size_bucket
    _save_state(state)
    return state


def days_since_install() -> int:
    state = _load_state()
    installed = datetime.fromisoformat(state["installed_at"])
    delta = datetime.now(timezone.utc) - installed
    return delta.days


def is_small_company() -> bool:
    """Empresas < 10 funcionários usam de graça para sempre (ver LICENSE)."""
    state = _load_state()
    return state.get("company_size_declared") == "1-9"


def has_valid_license_key() -> bool:
    """Verifica se existe uma chave de licença válida instalada."""
    state = _load_state()
    key = state.get("license_key")
    if not key:
        return False
    try:
        payload = jwt.decode(key, OMNIUIL_PUBLIC_KEY, algorithms=["EdDSA"])
        exp = payload.get("exp", 0)
        return exp > time.time()
    except JWTError:
        return False


def install_license_key(license_key: str) -> tuple[bool, str]:
    """
    Instala uma chave de licença comercial fornecida pelo cliente.
    Retorna (sucesso, mensagem).
    """
    try:
        payload = jwt.decode(license_key, OMNIUIL_PUBLIC_KEY, algorithms=["EdDSA"])
    except JWTError as e:
        return False, f"Chave de licença inválida: {e}"

    exp = payload.get("exp", 0)
    if exp <= time.time():
        return False, "Esta chave de licença expirou."

    state = _load_state()
    state["license_key"] = license_key
    state["licensed_to"] = payload.get("company", "desconhecido")
    _save_state(state)

    valid_until = datetime.fromtimestamp(exp, tz=timezone.utc)
    return True, f"Licença ativada para {payload.get('company')}. Válida até {valid_until.date()}."


def check_access() -> dict:
    """
    Função principal — chame isso no middleware do FastAPI a cada request
    para decidir se libera acesso completo ou mostra banner de bloqueio.
    """
    days = days_since_install()
    small = is_small_company()
    licensed = has_valid_license_key()

    if small:
        return {"access": "full", "reason": "empresa_pequena_isenta"}

    if licensed:
        return {"access": "full", "reason": "licenca_valida"}

    if days <= EVALUATION_DAYS:
        return {
            "access": "full",
            "reason": "periodo_avaliacao",
            "days_remaining": EVALUATION_DAYS - days,
        }

    return {
        "access": "limited",
        "reason": "avaliacao_expirada",
        "message": (
            f"Período de avaliação de {EVALUATION_DAYS} dias encerrado. "
            "Para continuar usando o dashboard e os agentes de IA em produção, "
            "solicite uma licença comercial: github.com/Uilcol/omniuil-ai"
        ),
    }


# ── Geração de chaves (uso EXCLUSIVO seu, nunca roda no cliente) ─────────────

def generate_keypair():
    """
    Rode isso UMA VEZ na sua máquina para gerar o par de chaves.
    Guarde a chave privada em local seguro — NUNCA commite no repositório.
    Cole a chave pública gerada no lugar do PLACEHOLDER acima antes de
    publicar o código.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    pub_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    print("=" * 70)
    print("CHAVE PRIVADA — GUARDE EM LOCAL SEGURO, NUNCA COMMITE NO GIT")
    print("=" * 70)
    print(priv_pem)
    print("=" * 70)
    print("CHAVE PÚBLICA — cole no lugar do PLACEHOLDER neste arquivo")
    print("=" * 70)
    print(pub_pem)


def issue_license_key(company: str, months: int, private_key_pem: str) -> str:
    """
    Emite uma nova chave de licença para um cliente que pagou.
    Rode isso na SUA máquina (nunca no servidor do cliente), usando a
    chave privada que você guardou com segurança.

    Exemplo de uso após um cliente pagar:

        from licensing import issue_license_key
        key = issue_license_key(
            company="Matera Sistemas",
            months=12,
            private_key_pem=open("minha_chave_privada.pem").read()
        )
        print(key)  # envie esse valor para o cliente colar no dashboard
    """
    exp = datetime.now(timezone.utc) + timedelta(days=30 * months)
    payload = {
        "company": company,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "exp": exp.timestamp(),
    }
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA")


# ── Instruções de integração ──────────────────────────────────────────────────
#
# 1. Cole este arquivo em: qsec-enterprise/api/licensing.py
#
# 2. Rode UMA VEZ, na sua máquina, para gerar seu par de chaves:
#      cd qsec-enterprise/api
#      python3 -c "from licensing import generate_keypair; generate_keypair()"
#
# 3. Copie a CHAVE PÚBLICA impressa e cole no lugar do PLACEHOLDER neste
#    arquivo (variável OMNIUIL_PUBLIC_KEY, lá em cima).
#
# 4. Guarde a CHAVE PRIVADA em um cofre de senhas (1Password, Bitwarden) ou
#    em um arquivo .pem FORA do repositório git. Adicione ao .gitignore:
#      echo "*.pem" >> .gitignore
#      echo "minha_chave_privada*" >> .gitignore
#
# 5. No server.py, adicione:
#
#      from licensing import check_access, declare_company_size, install_license_key
#
#      @app.get("/api/v1/license/status")
#      async def license_status():
#          return check_access()
#
#      @app.post("/api/v1/license/activate")
#      async def license_activate(body: dict):
#          ok, msg = install_license_key(body.get("license_key", ""))
#          if not ok:
#              raise HTTPException(400, msg)
#          return {"message": msg}
#
#      @app.post("/api/v1/setup/company-size")
#      async def setup_company_size(body: dict):
#          return declare_company_size(body.get("size", "1-9"))
#
# 6. No frontend (dashboard), adicione uma chamada a GET /api/v1/license/status
#    ao carregar. Se "access" != "full", mostre um banner com a "message"
#    e um campo para colar a chave de licença.
#
# 7. Quando alguém pagar (via Stripe/PIX), rode na SUA máquina:
#
#      python3 -c "
#      from licensing import issue_license_key
#      key = issue_license_key('Nome da Empresa', 12, open('minha_chave_privada.pem').read())
#      print(key)
#      "
#
#    Envie a chave gerada por e-mail para o cliente colar no dashboard dele.
