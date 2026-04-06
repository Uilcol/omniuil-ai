"""
AnalysisAgent — Analista de segurança com IA.

Responsabilidades:
  - Interpreta findings com contexto de negócio
  - Avalia risco real (não apenas técnico)
  - Prioriza o que corrigir primeiro
  - Estima esforço de migração
  - Gera plano de ação ordenado e executável
  - Decide quais findings mandar para RemediationAgent
"""

from __future__ import annotations

import json

from agents.base_agent import BaseAgent
from memory.shared_memory import SharedMemory
from tools.qsec_tools import QSEC_TOOLS


class AnalysisAgent(BaseAgent):

    def __init__(self, memory: SharedMemory):
        super().__init__(memory)

    @property
    def name(self) -> str:
        return "AnalysisAgent"

    @property
    def system_prompt(self) -> str:
        return """Você é o AnalysisAgent do sistema QSEC — engenheiro sênior de segurança quântica com 15 anos de experiência em criptografia aplicada.

## Sua missão
Transformar findings brutos do scanner em inteligência acionável: contexto, risco real, priorização e plano de migração.

## Suas responsabilidades
1. Receber lista de findings e analisar o contexto de cada um
2. Avaliar o risco real combinando: severidade técnica + contexto de uso + dados expostos
3. Calcular o "Quantum Risk Score" de 0-100 para o projeto
4. Priorizar por: (a) dados mais sensíveis em risco, (b) facilidade de exploração, (c) esforço de correção
5. Gerar plano de migração por fases (Quick Wins → Esforço Médio → Long Term)
6. Identificar dependências entre correções (ex: corrigir JWT antes de API keys)

## Framework de análise — Quantum Risk Score
```
Score = (critical * 25 + high * 10 + medium * 3 + low * 1) 
         * contexto_multiplicador
         * exposição_multiplicador

contexto_multiplicador:
  - Produção direta:    2.0x
  - Dados financeiros:  1.8x
  - Dados pessoais:     1.6x
  - Infraestrutura:     1.5x
  - Desenvolvimento:    0.5x

exposição_multiplicador:
  - Internet-facing API: 2.0x
  - Serviço interno:     1.2x
  - CLI/Ferramenta:      0.8x
  - Lib/SDK:             1.5x (afeta todos os usuários)
```

## Formato de saída obrigatório
```json
{
  "quantum_risk_score": 85,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "executive_summary": "...",
  "top_3_priorities": [
    {"rank": 1, "finding": "QSC-001 RSA em auth.rs", "reason": "...", "effort": "HIGH", "impact": "CRITICAL"}
  ],
  "migration_plan": {
    "phase_1_quick_wins": [{"action": "...", "files": [], "effort_days": 1}],
    "phase_2_medium":     [{"action": "...", "files": [], "effort_days": 5}],
    "phase_3_long_term":  [{"action": "...", "files": [], "effort_days": 30}]
  },
  "send_to_remediation": ["file1.rs", "file2.rs"],
  "requires_incident_response": false
}
```

## Princípios
- Contexto > Severidade bruta. Um MD5 em dados bancários > RSA em arquivo de config.
- Sempre considere: "E se um adversário tiver um computador quântico hoje?"
- Seja concreto: o desenvolvedor precisa saber EXATAMENTE o que fazer amanhã.
- Nunca subestime HNDL (Harvest Now, Decrypt Later) — é uma ameaça real e ativa.
"""

    @property
    def tools(self) -> list[dict]:
        return [t for t in QSEC_TOOLS if t["name"] in {
            "get_engine_info",
            "read_file_content",
            "send_alert",
            "run_full_pipeline",
        }]

    async def analyze(self, findings: list[dict], project_context: dict | None = None) -> dict:
        """
        Analisa findings e retorna plano de ação priorizado.
        """
        context = {
            "findings":        findings,
            "project_context": project_context or {},
            "findings_count":  len(findings),
            "by_severity": {
                "CRITICAL": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                "HIGH":     len([f for f in findings if f.get("severity") == "HIGH"]),
                "MEDIUM":   len([f for f in findings if f.get("severity") == "MEDIUM"]),
                "LOW":      len([f for f in findings if f.get("severity") == "LOW"]),
            }
        }

        result = await self.run(
            task="""Analise os findings de segurança criptográfica fornecidos no contexto.

Passos obrigatórios:
1. Calcule o Quantum Risk Score do projeto
2. Identifique os top 3 riscos mais críticos com justificativa
3. Crie o plano de migração em 3 fases (Quick Wins, Médio Prazo, Long Term)
4. Determine quais arquivos enviar para o RemediationAgent
5. Avalie se algum finding exige resposta a incidente imediata
6. Retorne o JSON estruturado conforme o formato especificado

Seja preciso, técnico e acionável. O destinatário é um time de engenharia.""",
            context=context
        )

        await self.memory.log_action(self.name, "analysis_complete", {
            "findings_analyzed": len(findings),
        })

        return {
            "agent":         self.name,
            "findings_count": len(findings),
            "analysis":      result["result"],
            "tool_calls":    result["tool_calls"],
        }
