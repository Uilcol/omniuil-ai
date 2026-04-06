"""
IncidentAgent — Resposta autônoma a incidentes de segurança.

Responsabilidades:
  - Responde a comprometimentos de chave em tempo real
  - Revoga tokens comprometidos
  - Força rotação de chaves
  - Avalia impacto (quais sistemas foram afetados?)
  - Gera relatório de incidente (post-mortem)
  - Coordena com outros agentes durante o incidente
  - Define janela de comprometimento (quando começou?)
"""

from __future__ import annotations

import time

from agents.base_agent import BaseAgent
from memory.shared_memory import SharedMemory, IncidentStatus
from tools.qsec_tools import QSEC_TOOLS, execute_tool


class IncidentAgent(BaseAgent):

    def __init__(self, memory: SharedMemory):
        super().__init__(memory)

    @property
    def name(self) -> str:
        return "IncidentAgent"

    @property
    def system_prompt(self) -> str:
        return """Você é o IncidentAgent do sistema QSEC — respondedor de incidentes de segurança criptográfica.

## Sua missão
Conter, mitigar e documentar incidentes de segurança criptográfica com velocidade e precisão cirúrgica.

## Tipos de incidentes que você responde

### INCIDENTE TIPO 1: Chave comprometida
Ações imediatas (em ordem):
1. `rotate_keys` — gera nova chave imediatamente
2. `send_alert` INCIDENT — notifica todos os sistemas
3. Documentar janela de comprometimento estimada
4. Listar todos os tokens emitidos com a chave comprometida
5. `revoke_token` para tokens de alto risco
6. Gerar relatório de impacto

### INCIDENTE TIPO 2: Credential hardcoded encontrada em produção
Ações:
1. `send_alert` CRITICAL imediatamente
2. Documentar quais ambientes foram afetados
3. Instruções para rotação manual (QSEC não tem acesso direto ao env)
4. Verificar se a credential aparece em outros arquivos (scan_codebase)
5. Gerar timeline do incidente

### INCIDENTE TIPO 3: JWT algorithm=none detectado em produção
Ações:
1. `send_alert` CRITICAL — tokens sem assinatura são inválidos por definição
2. `revoke_token` para qualquer token suspeito
3. Instruções para reemissão com PQC-JWT
4. Verificar logs de acesso (período de exposição)

### INCIDENTE TIPO 4: Dependência vulnerável crítica (QSC-040+)
Ações:
1. Avaliar se a vulnerabilidade é explorável no contexto
2. Verificar se há versão corrigida disponível
3. `send_alert` com severidade adequada
4. Plano de atualização de emergência

## Estrutura do relatório de incidente (post-mortem)
```json
{
  "incident_report": {
    "id":                "INC-XXXXXXXX",
    "type":              "key_compromise|hardcoded_cred|jwt_none|vuln_dep",
    "severity":          "CRITICAL|HIGH|MEDIUM",
    "detected_at":       "ISO8601",
    "estimated_start":   "ISO8601",
    "containment_time":  "X minutes",
    "root_cause":        "...",
    "affected_systems":  [],
    "actions_taken":     [],
    "tokens_revoked":    0,
    "keys_rotated":      0,
    "status":            "CONTAINED|RESOLVED|MONITORING",
    "next_steps":        [],
    "lessons_learned":   "..."
  }
}
```

## Princípios de resposta a incidente
- Velocidade > Perfeição no primeiro momento. Contenha primeiro, investigue depois.
- Registre tudo com timestamps. O post-mortem começa no segundo 0.
- Errar na direção do conservador: revogar token a mais é melhor que deixar comprometido.
- Comunique claramente: o que aconteceu, quem é afetado, o que fazer agora.
"""

    @property
    def tools(self) -> list[dict]:
        return [t for t in QSEC_TOOLS if t["name"] in {
            "rotate_keys",
            "revoke_token",
            "scan_codebase",
            "send_alert",
            "get_engine_info",
            "create_api_key",
            "read_file_content",
        }]

    async def respond(
        self,
        incident_type: str,
        description:   str,
        context:       dict | None = None,
    ) -> dict:
        """
        Responde a um incidente de segurança.

        Args:
            incident_type: "key_compromise" | "hardcoded_cred" | "jwt_none" | "vuln_dep"
            description:   Descrição do incidente
            context:       Dados adicionais (arquivo afetado, token, etc.)
        """
        # Abre incidente na SharedMemory
        incident = await self.memory.open_incident(
            title=f"[{incident_type.upper()}] {description[:80]}",
            description=description,
            severity="CRITICAL",
            agent=self.name,
        )

        result = await self.run(
            task=f"""INCIDENTE DE SEGURANÇA DETECTADO — Responda imediatamente.

TIPO: {incident_type}
ID: {incident.id}
DESCRIÇÃO: {description}

Inicie o protocolo de resposta a incidente para este tipo:
1. Execute as ações de contenção imediata
2. Documente cada ação com timestamp
3. Avalie o impacto total
4. Gere o relatório de incidente completo em JSON

PRIORIDADE MÁXIMA — cada segundo conta.""",
            context={
                "incident_id":   incident.id,
                "incident_type": incident_type,
                "description":   description,
                **(context or {}),
            }
        )

        # Resolve incidente na memória
        await self.memory.resolve_incident(
            incident.id,
            resolution=f"Response executed by {self.name}. See report for details."
        )

        await self.memory.log_action(self.name, "incident_responded", {
            "incident_id":   incident.id,
            "incident_type": incident_type,
        })

        return {
            "agent":         self.name,
            "incident_id":   incident.id,
            "incident_type": incident_type,
            "report":        result["result"],
            "tool_calls":    result["tool_calls"],
            "success":       result["success"],
        }

    async def respond_to_key_compromise(self, key_id: str, reason: str) -> dict:
        """Atalho para comprometimento de chave."""
        return await self.respond(
            incident_type="key_compromise",
            description=f"Key {key_id} may be compromised: {reason}",
            context={"key_id": key_id, "reason": reason},
        )

    async def respond_to_hardcoded_credential(self, file_path: str, line: int) -> dict:
        """Atalho para credencial hardcoded em produção."""
        return await self.respond(
            incident_type="hardcoded_cred",
            description=f"Hardcoded credential found in production: {file_path}:{line}",
            context={"file_path": file_path, "line": line},
        )
