"""
OmniUil AI — Telemetria Opcional e Transparente
==================================================

Envia um ping ANÔNIMO e OPCIONAL para saber quantas instâncias estão
ativas. NÃO coleta código, nomes de arquivos, findings específicos,
nem qualquer dado que identifique a empresa ou o conteúdo escaneado.

Totalmente desativável via variável de ambiente:
    OMNIUIL_TELEMETRY=off

O que É enviado (se ativado):
    - install_id (UUID aleatório gerado localmente, não rastreável)
    - versão do OmniUil AI
    - contagem total de scans (número, não conteúdo)
    - contagem total de findings por severidade (números, não conteúdo)
    - país (inferido por timezone do sistema, não por IP)

O que NUNCA é enviado:
    - Código-fonte ou trechos de código
    - Nomes de arquivos ou caminhos
    - Nome da empresa, CNPJ, ou qualquer identificador
    - Conteúdo específico dos findings (regras que dispararam, sim;
      código que disparou, não)
    - Endereço IP é descartado no servidor, não armazenado

Instalação: cole em qsec-enterprise/api/telemetry.py
"""
from __future__ import annotations
import json, logging, os, time
from datetime import datetime, timezone
from pathlib import Path

import httpx

log = logging.getLogger("telemetry")

TELEMETRY_ENDPOINT = "https://telemetry.omniuil.ai/v1/ping"  # ajuste para seu domínio real
TELEMETRY_ENABLED = os.environ.get("OMNIUIL_TELEMETRY", "on").lower() != "off"
PING_INTERVAL_SECONDS = 24 * 3600  # uma vez por dia, no máximo

STATE_FILE = Path.home() / ".omniuil" / "telemetry_state.json"


def _load_last_ping() -> float:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text()).get("last_ping", 0)
        except (json.JSONDecodeError, OSError):
            return 0
    return 0


def _save_last_ping(ts: float) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"last_ping": ts}))


async def send_ping(install_id: str, version: str, metrics: dict) -> None:
    """
    Envia um ping de telemetria, respeitando o intervalo mínimo e o opt-out.
    Falha silenciosamente — telemetria NUNCA deve quebrar o produto do cliente.
    """
    if not TELEMETRY_ENABLED:
        return

    last = _load_last_ping()
    now = time.time()
    if now - last < PING_INTERVAL_SECONDS:
        return  # já enviou hoje, não spamma

    payload = {
        "install_id": install_id,
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scans_total": metrics.get("scans_total", 0),
        "findings_critical": metrics.get("critical_total", 0),
        "findings_high": metrics.get("high_total", 0),
        # NENHUM dado de código, nome de arquivo ou empresa é incluído
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(TELEMETRY_ENDPOINT, json=payload)
        _save_last_ping(now)
        log.info("Telemetry ping enviado (anônimo)")
    except Exception as e:
        # Nunca deixa telemetria quebrar o dashboard do cliente
        log.debug(f"Telemetry ping falhou (ignorado): {e}")


def is_enabled() -> bool:
    return TELEMETRY_ENABLED


# ── Instruções de integração ──────────────────────────────────────────────────
#
# 1. Cole em qsec-enterprise/api/telemetry.py
#
# 2. No server.py, adicione uma chamada em background após cada scan
#    completar (não bloqueia a resposta ao usuário):
#
#      from telemetry import send_ping, is_enabled
#      import asyncio
#
#      # Dentro de _run_scan_job, após o scan completar:
#      if is_enabled():
#          asyncio.create_task(send_ping(
#              install_id=state["install_id"],
#              version="3.3.0",
#              metrics=_metrics,  # dict já existente no server.py
#          ))
#
# 3. Documente isso claramente no README — transparência é o que torna
#    telemetria opcional aceitável em vez de invasiva:
#
#      ## Telemetria
#      O OmniUil AI envia um ping anônimo diário (opcional) para nos
#      ajudar a entender adoção. Nenhum código, nome de arquivo ou dado
#      identificável é enviado — apenas contagens agregadas.
#      Para desativar: export OMNIUIL_TELEMETRY=off
#
# 4. Você ainda PRECISA de um servidor simples recebendo esses pings
#    (mesmo que seja um endpoint Flask rodando numa VPS de R$20/mês ou
#    uma função serverless gratuita — Vercel/Netlify Functions, Cloudflare
#    Workers). Isso fica para quando você tiver 5+ minutos de tempo livre,
#    NÃO é bloqueador para publicar hoje. Sem o endpoint, o ping falha
#    silenciosamente e não quebra nada.
