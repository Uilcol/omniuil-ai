"""
MonitoringAgent — Vigilância contínua de projetos.

Responsabilidades:
  - Monitora diretórios por mudanças de arquivos
  - Re-escaneia automaticamente quando código muda
  - Detecta regressões (nova crypto fraca introduzida)
  - Monitora vencimento de chaves criptográficas
  - Alerta sobre dependências vulneráveis novas
  - Mantém histórico de tendências (melhorando ou piorando?)
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from pathlib import Path

from agents.base_agent import BaseAgent
from memory.shared_memory import SharedMemory
from tools.qsec_tools import QSEC_TOOLS, execute_tool


class MonitoringAgent(BaseAgent):

    def __init__(self, memory: SharedMemory):
        super().__init__(memory)
        self._file_hashes:  dict[str, str]   = {}  # path → SHA256 do conteúdo
        self._running:      bool             = False
        self._watch_paths:  set[str]         = set()
        self._scan_cooldown: dict[str, float] = {}  # evita re-scan muito rápido

    @property
    def name(self) -> str:
        return "MonitoringAgent"

    @property
    def system_prompt(self) -> str:
        return """Você é o MonitoringAgent do sistema QSEC — vigia contínuo da postura de segurança criptográfica.

## Sua missão
Manter vigilância permanente sobre projetos monitorados. Detectar regressões antes que cheguem à produção.

## Suas responsabilidades
1. Analisar mudanças detectadas em arquivos de código
2. Avaliar se a mudança introduziu nova vulnerabilidade (regressão)
3. Comparar com o baseline anterior (estava clean, agora tem RSA = regressão crítica)
4. Verificar status de chaves criptográficas (próximas ao vencimento?)
5. Monitorar SBOM por novas dependências vulneráveis
6. Decidir a urgência da resposta: imediata vs. próximo ciclo de scan

## Classificação de eventos
- REGRESSÃO CRÍTICA: código anteriormente limpo agora tem CRITICAL finding → alerta imediato + acionar ScannerAgent + RemediationAgent
- NOVA DEPENDÊNCIA VULN: Cargo.toml mudou e nova dep tem QSC-040+ → alerta HIGH
- VENCIMENTO DE CHAVE: chave expira em < 7 dias → alerta WARNING + acionar rotação
- MELHORIA: finding resolvido → alerta INFO positivo
- SEM MUDANÇA RELEVANTE: apenas log

## Baseline de comparação
Compare sempre com o último snapshot da SharedMemory.
Se não há baseline → scan completo é o baseline.

## Princípios
- Vigilância sem ruído. Alertas precisos > alertas frequentes.
- Regressões têm prioridade máxima — código novo é mais fácil de corrigir.
- Não escaneie o mesmo arquivo mais de uma vez por minuto (cooldown).
"""

    @property
    def tools(self) -> list[dict]:
        return [t for t in QSEC_TOOLS if t["name"] in {
            "scan_codebase",
            "get_engine_info",
            "send_alert",
            "read_file_content",
            "generate_sbom",
        }]

    def add_watch_path(self, path: str) -> None:
        """Adiciona um diretório para monitoramento."""
        self._watch_paths.add(path)
        self.memory.monitored_paths.add(path)
        # Inicializa hashes dos arquivos atuais
        self._snapshot_directory(path)

    def _snapshot_directory(self, directory: str) -> None:
        """Captura hashes de todos os arquivos relevantes."""
        root = Path(directory)
        if not root.exists():
            return
        for ext in ("*.rs", "*.py", "*.go", "*.java", "*.js", "*.ts", "Cargo.toml"):
            for f in root.rglob(ext):
                if not any(skip in str(f) for skip in ("target", ".git", "__pycache__", "node_modules")):
                    try:
                        content = f.read_bytes()
                        self._file_hashes[str(f)] = hashlib.sha256(content).hexdigest()
                    except Exception:
                        pass

    def _detect_changes(self, directory: str) -> list[str]:
        """Retorna lista de arquivos que mudaram desde o último snapshot."""
        changed = []
        root    = Path(directory)
        if not root.exists():
            return changed

        for ext in ("*.rs", "*.py", "*.go", "*.java", "*.js", "*.ts", "Cargo.toml"):
            for f in root.rglob(ext):
                if any(skip in str(f) for skip in ("target", ".git", "__pycache__")):
                    continue
                try:
                    content     = f.read_bytes()
                    current_hash = hashlib.sha256(content).hexdigest()
                    path_str    = str(f)
                    old_hash    = self._file_hashes.get(path_str)

                    if old_hash is None:
                        # Arquivo novo
                        changed.append(path_str)
                        self._file_hashes[path_str] = current_hash
                    elif old_hash != current_hash:
                        # Arquivo modificado
                        changed.append(path_str)
                        self._file_hashes[path_str] = current_hash
                except Exception:
                    pass

        return changed

    async def run_watch_cycle(self) -> dict:
        """
        Executa um ciclo de monitoramento sobre todos os paths registrados.
        Chamado periodicamente pelo Orchestrator.
        """
        all_changed: list[str] = []

        for watch_path in self._watch_paths:
            changed = self._detect_changes(watch_path)
            all_changed.extend(changed)

        if not all_changed:
            return {"agent": self.name, "status": "no_changes", "changed_files": []}

        # Filtra arquivos em cooldown (não re-escanear < 60s)
        now = time.time()
        to_scan = [
            f for f in all_changed
            if now - self._scan_cooldown.get(f, 0) > 60
        ]
        for f in to_scan:
            self._scan_cooldown[f] = now

        if not to_scan:
            return {"agent": self.name, "status": "cooldown", "changed_files": all_changed}

        # Pede ao agente para analisar as mudanças
        result = await self.run(
            task=f"""Analise as mudanças detectadas nos seguintes {len(to_scan)} arquivo(s):
{chr(10).join(f'- {f}' for f in to_scan[:10])}

Para cada arquivo:
1. Escaneie com scan_codebase
2. Avalie se há regressão (nova vulnerabilidade não existente antes)
3. Envie alerta apropriado (CRITICAL se regressão, INFO se melhoria)
4. Recomende ação imediata se necessário

Contexto: mudanças detectadas por monitoramento contínuo.""",
            context={
                "changed_files":     to_scan,
                "previous_findings": len(self.memory.findings),
                "watch_paths":       list(self._watch_paths),
            }
        )

        # Registra novos findings
        for f in to_scan:
            scan_result = execute_tool("scan_codebase", {"path": f})
            findings    = scan_result.get("findings", [])
            if findings:
                await self.memory.add_findings(findings, f, self.name)

        return {
            "agent":         self.name,
            "status":        "changes_detected",
            "changed_files": to_scan,
            "analysis":      result["result"],
        }

    async def check_key_expiry(self) -> dict:
        """Verifica se alguma chave criptográfica está próxima do vencimento."""
        result = await self.run(
            task="""Verifique o status das chaves criptográficas do sistema QSEC.

1. Use get_engine_info para obter status das chaves
2. Identifique chaves expirando em menos de 7 dias
3. Envie alerta WARNING para cada chave próxima ao vencimento
4. Recomende rotação preventiva se necessário

Seja específico sobre qual chave e quanto tempo falta.""",
            context={}
        )
        return {"agent": self.name, "key_check": result["result"]}
