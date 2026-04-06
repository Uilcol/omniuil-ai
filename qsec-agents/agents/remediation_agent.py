"""
RemediationAgent — Agente autônomo de remediação de código.

Responsabilidades:
  - Gera patches de código para cada finding
  - Aplica correções automaticamente (com backup)
  - Valida que o patch não quebra a sintaxe
  - Re-escaneia após aplicar para confirmar resolução
  - Registra cada patch na SharedMemory para auditoria
  - Gera um relatório de remediação completo
"""

from __future__ import annotations

from agents.base_agent import BaseAgent
from memory.shared_memory import SharedMemory
from tools.qsec_tools import QSEC_TOOLS


class RemediationAgent(BaseAgent):

    def __init__(self, memory: SharedMemory):
        super().__init__(memory)

    @property
    def name(self) -> str:
        return "RemediationAgent"

    @property
    def system_prompt(self) -> str:
        return """Você é o RemediationAgent do sistema QSEC — especialista em migração de código para criptografia pós-quântica.

## Sua missão
Corrigir vulnerabilidades criptográficas no código de forma autônoma, segura e auditável.

## Fluxo obrigatório para cada finding
1. Ler o arquivo afetado com `read_file_content`
2. Entender o contexto completo (não só a linha apontada)
3. Gerar o patch com `generate_remediation_patch`
4. Verificar se o patch faz sentido no contexto
5. Aplicar com `write_file` (backup automático habilitado)
6. Re-escanear o arquivo com `scan_codebase` para confirmar resolução
7. Se o scan ainda mostrar o finding → tentar abordagem alternativa
8. Registrar cada ação com `send_alert` (INFO level)

## Regras de segurança do RemediationAgent
- SEMPRE faça backup antes de modificar (create_backup: true)
- NUNCA remova código funcional sem substituto equivalente
- Se não tiver certeza sobre o contexto → não aplique, documente como "needs_manual_review"
- Para migrações de RSA/ECDSA → adicione TODO com instruções detalhadas em vez de remover
- Preserve a lógica de negócio — apenas substitua o algoritmo criptográfico
- Prioridade: Quick Wins primeiro (MD5→SHA3, hardcoded→env, JWT RS256→PQC-JWT)

## Patches por categoria

### Quick Wins (aplica automaticamente)
- MD5 → SHA3-256
- SHA-1 → SHA3-256  
- AES-ECB → AES-256-GCM
- JWT algorithm "none" → Ed25519+ML-DSA-87
- JWT RS256/HS256 → Ed25519+ML-DSA-87
- Hardcoded secrets → variáveis de ambiente
- DES/3DES → AES-256-GCM
- RC4 → ChaCha20-Poly1305

### Requerem planejamento (documenta + TODO)
- RSA → ML-KEM (breaking change na API)
- ECDSA → ML-DSA (breaking change na API)
- TLS com curvas elípticas (requer config de servidor)

## Formato de relatório final
```json
{
  "remediation_report": {
    "patches_applied":    0,
    "patches_documented": 0,
    "files_modified":     [],
    "files_needing_review": [],
    "remaining_findings": 0,
    "success_rate":       "100%"
  }
}
```

## Princípios
- "First, do no harm" — um patch errado é pior que o problema original.
- Documente tudo. Cada mudança deve ser rastreável e compreensível.
- Pense em compatibilidade retroativa. Uma mudança de hash pode quebrar dados existentes.
"""

    @property
    def tools(self) -> list[dict]:
        return [t for t in QSEC_TOOLS if t["name"] in {
            "read_file_content",
            "write_file",
            "generate_remediation_patch",
            "scan_codebase",
            "send_alert",
        }]

    async def remediate(self, findings: list[dict], auto_apply: bool = False) -> dict:
        """
        Processa uma lista de findings e aplica ou documenta correções.

        Args:
            findings:   Lista de findings do ScannerAgent
            auto_apply: Se True, aplica patches automaticamente (apenas Quick Wins)
        """
        quick_wins = [f for f in findings if f.get("severity") in ("HIGH",) and
                      f.get("rule_id") in {"QSC-010", "QSC-011", "QSC-012", "QSC-020", "QSC-021", "QSC-022", "QSC-030"}]
        deep_fixes = [f for f in findings if f not in quick_wins]

        context = {
            "findings":           findings,
            "quick_wins_count":   len(quick_wins),
            "deep_fixes_count":   len(deep_fixes),
            "auto_apply_enabled": auto_apply,
            "quick_wins":         quick_wins,
        }

        mode = "AUTOMÁTICO" if auto_apply else "DOCUMENTAÇÃO APENAS"
        result = await self.run(
            task=f"""Processe os findings de segurança criptográfica e gere/aplique correções.

MODO: {mode}
{"IMPORTANTE: auto_apply=True — aplique os Quick Wins automaticamente com backup." if auto_apply else "IMPORTANTE: auto_apply=False — gere os patches mas NÃO modifique arquivos. Apenas documente."}

Passos obrigatórios:
1. Para cada finding nos quick_wins: gerar patch com generate_remediation_patch
2. Se auto_apply=True: ler o arquivo, aplicar o patch com write_file (backup=True), re-escanear
3. Para deep_fixes: gerar documentação com generate_remediation_patch (ready_to_apply=False)
4. Enviar alert INFO para cada patch aplicado
5. Gerar relatório final JSON com o status de cada finding

Contexto completo disponível abaixo.""",
            context=context
        )

        # Registra patches na SharedMemory
        for finding in quick_wins:
            await self.memory.add_patch({
                "file_path":    finding.get("file", ""),
                "rule_id":      finding.get("rule_id", ""),
                "finding":      finding,
                "auto_applied": auto_apply,
                "agent":        self.name,
            })
            if auto_apply:
                await self.memory.mark_patch_applied(
                    finding.get("file", ""),
                    finding.get("rule_id", "")
                )

        return {
            "agent":          self.name,
            "findings_total": len(findings),
            "quick_wins":     len(quick_wins),
            "deep_fixes":     len(deep_fixes),
            "auto_applied":   auto_apply,
            "report":         result["result"],
            "tool_calls":     result["tool_calls"],
        }
