"""
ScannerAgent — Agente autônomo de detecção de crypto fraca.

Responsabilidades:
  - Escaneia projetos autonomamente
  - Prioriza findings por severidade e contexto
  - Detecta regressões (novo código vulnerável desde último scan)
  - Decide se deve acionar outros agentes (Analysis, Remediation, Incident)
  - Armazena resultados na SharedMemory
"""

from __future__ import annotations

from agents.base_agent import BaseAgent
from memory.shared_memory import SharedMemory
from tools.qsec_tools import QSEC_TOOLS


class ScannerAgent(BaseAgent):

    def __init__(self, memory: SharedMemory):
        super().__init__(memory)

    @property
    def name(self) -> str:
        return "ScannerAgent"

    @property
    def system_prompt(self) -> str:
        return """Você é o ScannerAgent do sistema QSEC — especialista em detecção de criptografia fraca e vulnerável a computadores quânticos.

## Sua missão
Escanear código-fonte de forma autônoma, identificar riscos criptográficos reais e reportar com precisão cirúrgica.

## Suas responsabilidades
1. Usar a ferramenta `scan_codebase` para escanear o projeto
2. Analisar os findings retornados e classificar por criticidade real
3. Identificar padrões: o mesmo erro em múltiplos arquivos? Dependência sistemática de RSA?
4. Detectar o tipo de dado protegido (autenticação vs. dados pessoais vs. secrets vs. transações)
5. Usar `send_alert` para findings CRITICAL imediatamente
6. Reportar um sumário estruturado e objetivo

## Critérios de escalação imediata
- QSC-001 (RSA) em código de produção → CRITICAL alert
- QSC-020 (JWT none) em qualquer lugar → CRITICAL alert + acionar IncidentAgent
- QSC-030 (hardcoded key) → CRITICAL alert + acionar IncidentAgent
- 5+ findings HIGH em único arquivo → WARNING alert

## Formato do relatório final
Sempre termine com um JSON estruturado:
```json
{
  "scan_summary": {
    "path": "...",
    "total": 0,
    "critical": 0,
    "high": 0,
    "top_risks": [],
    "needs_immediate_action": true/false,
    "recommended_next_agents": ["AnalysisAgent", "RemediationAgent"]
  }
}
```

## Princípios
- Seja objetivo. Sem alarmismo desnecessário mas sem minimizar riscos reais.
- Contexto importa: RSA num arquivo de teste é diferente de RSA em produção.
- Sempre use as ferramentas disponíveis — não invente findings.
"""

    @property
    def tools(self) -> list[dict]:
        return [t for t in QSEC_TOOLS if t["name"] in {
            "scan_codebase",
            "get_engine_info",
            "send_alert",
            "read_file_content",
        }]

    async def scan_project(self, project_path: str) -> dict:
        """Ponto de entrada principal: escaneia um projeto."""
        result = await self.run(
            task=f"""Escaneie o projeto em '{project_path}' em busca de criptografia fraca ou vulnerável a computadores quânticos.

Passos obrigatórios:
1. Execute scan_codebase em '{project_path}'
2. Analise cada finding com contexto (onde está, qual o risco real)
3. Envie alert CRITICAL para qualquer finding de severidade CRITICAL
4. Gere o sumário final estruturado em JSON

Seja preciso, objetivo e acione os alertas adequados.""",
            context={"project_path": project_path}
        )

        # Extrai findings da SharedMemory e registra scan
        from tools.qsec_tools import execute_tool
        scan_result = execute_tool("scan_codebase", {"path": project_path})
        findings    = scan_result.get("findings", [])
        await self.memory.add_findings(findings, project_path, self.name)
        self.memory.monitored_paths.add(project_path)

        return {
            "agent":          self.name,
            "project_path":   project_path,
            "findings_count": len(findings),
            "analysis":       result["result"],
            "tool_calls":     result["tool_calls"],
        }
