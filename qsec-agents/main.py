"""
QSEC Multi-Agent System — Entry Point

Uso:
  python main.py audit    <project>  [--auto-remediate]
  python main.py monitor  <project>  [--interval 30]
  python main.py incident <type>     --desc "descrição"
  python main.py supply   <project>  [--artifacts a,b]
  python main.py keys     status|rotate|revoke
  python main.py demo
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()

# Verifica ANTHROPIC_API_KEY antes de importar agentes
if not os.environ.get("ANTHROPIC_API_KEY"):
    # Tenta carregar de .env
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                os.environ["ANTHROPIC_API_KEY"] = line.split("=", 1)[1].strip().strip('"')
                break

from orchestrator import QsecOrchestrator


async def cmd_audit(args) -> None:
    orch = QsecOrchestrator()
    await orch.full_security_audit(
        project_path=args.project,
        auto_remediate=args.auto_remediate,
    )


async def cmd_monitor(args) -> None:
    orch = QsecOrchestrator()
    paths = args.paths if hasattr(args, "paths") else [args.project]
    await orch.continuous_monitoring(
        watch_paths=paths,
        interval_secs=args.interval,
    )


async def cmd_incident(args) -> None:
    orch = QsecOrchestrator()
    await orch.respond_to_incident(
        incident_type=args.type,
        description=args.desc,
        context={"file": getattr(args, "file", ""), "key_id": getattr(args, "key_id", "")},
    )


async def cmd_supply(args) -> None:
    orch = QsecOrchestrator()
    artifacts = args.artifacts.split(",") if getattr(args, "artifacts", "") else []
    await orch.supply_chain_security(
        project_path=args.project,
        artifacts=artifacts,
        output_dir=getattr(args, "out_dir", "./qsec-out"),
    )


async def cmd_keys(args) -> None:
    orch = QsecOrchestrator()
    result = await orch.key_lifecycle(
        action=args.action,
        key_id=getattr(args, "key_id", ""),
        reason=getattr(args, "reason", ""),
    )
    import json
    console.print(json.dumps(result, indent=2, default=str))


async def cmd_demo() -> None:
    """
    Demo completo do sistema multi-agente sem necessidade de API key real.
    Usa o modo simulação do engine Rust.
    """
    console.print(Panel(
        "[bold cyan]QSEC Multi-Agent System — Demo[/bold cyan]\n\n"
        "Este demo executa o workflow completo:\n"
        "  1. ScannerAgent     → detecta crypto fraca\n"
        "  2. AnalysisAgent    → analisa risco com IA\n"
        "  3. RemediationAgent → gera plano de correção\n"
        "  4. IncidentAgent    → responde a finding crítico\n"
        "  5. MonitoringAgent  → ciclo de monitoramento\n",
        title="🚀 Demo Mode",
    ))

    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print(
            "\n[yellow]⚠️  ANTHROPIC_API_KEY não encontrada.[/yellow]\n"
            "Configure em .env ou export ANTHROPIC_API_KEY=sk-ant-...\n"
            "Sem a chave, os agentes usam respostas simuladas.\n"
        )
        await _run_demo_simulated()
        return

    # Demo real com Claude API
    orch = QsecOrchestrator()

    # Cria projeto de demo temporário
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_demo_project(tmpdir)

        console.print(f"\n[dim]Demo project created at: {tmpdir}[/dim]\n")

        # Workflow 1: Auditoria completa
        await orch.full_security_audit(tmpdir, auto_remediate=False)

        # Workflow 3: Resposta a incidente
        console.print("\n[bold red]Simulating incident response...[/bold red]")
        await orch.respond_to_incident(
            "hardcoded_cred",
            "API key encontrada hardcoded em src/secrets.rs linha 5",
            {"file": f"{tmpdir}/src/secrets.rs", "line": 5}
        )


def _create_demo_project(tmpdir: str) -> None:
    """Cria projeto de demo com vulnerabilidades intencionais."""
    root = Path(tmpdir)
    (root / "src").mkdir()

    (root / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "1.0.0"\n\n'
        '[dependencies]\nserde = "1"\nring = "0.17"\nopenssl = "0.10"\n'
    )
    (root / "src" / "crypto.rs").write_text(
        'use rsa::RsaPrivateKey;\nuse md5;\n\n'
        'fn hash(data: &[u8]) -> Vec<u8> { Md5::new().chain_update(data).finalize().to_vec() }\n'
        'fn gen_key() -> RsaPrivateKey { RSA::generate(2048) }\n'
    )
    (root / "src" / "auth.rs").write_text(
        'use jsonwebtoken::Algorithm;\n\n'
        'const JWT_ALG: Algorithm = Algorithm::RS256;\n'
        'fn verify(token: &str) { /* ... */ }\n'
    )
    (root / "src" / "secrets.rs").write_text(
        'fn get_key() -> &\'static str {\n'
        '    let api_key = "prod_sk_a1b2c3d4e5f6789012345678";\n'
        '    api_key\n'
        '}\n'
    )


async def _run_demo_simulated() -> None:
    """Demo sem API key — mostra a estrutura do sistema."""
    from tools.qsec_tools import execute_tool
    from memory.shared_memory import SharedMemory
    from rich.table import Table
    import json

    console.print("\n[bold]Executando demo simulado (sem Claude API)...[/bold]\n")

    mem = SharedMemory()

    # Simula scan
    console.print("[blue]1/4 ScannerAgent — scanning demo project...[/blue]")
    result = execute_tool("scan_codebase", {"path": "./demo-project"})
    findings = result.get("findings", [])
    await mem.add_findings(findings, "./demo-project", "ScannerAgent")

    table = Table(title=f"Findings ({len(findings)} total)")
    table.add_column("Severity"); table.add_column("Rule"); table.add_column("Title"); table.add_column("File")
    colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}
    for f in findings:
        sev = f.get("severity", "LOW")
        table.add_row(f"[{colors[sev]}]{sev}[/]", f.get("rule_id",""), f.get("title","")[:45], f.get("file","?").split("/")[-1])
    console.print(table)

    # Simula analysis
    console.print("\n[blue]2/4 AnalysisAgent — risk analysis (simulated)...[/blue]")
    crit = len([f for f in findings if f.get("severity") == "CRITICAL"])
    high = len([f for f in findings if f.get("severity") == "HIGH"])
    score = min(100, crit * 25 + high * 10)
    console.print(Panel(
        f"Quantum Risk Score: [red]{score}/100[/red]\n"
        f"Critical: {crit}  High: {high}\n\n"
        "Top Priority: QSC-001 RSA → migrate to ML-KEM-1024\n"
        "Phase 1 Quick Wins: MD5→SHA3, JWT RS256→PQC-JWT, hardcoded→env\n"
        "Estimated effort: 3-5 days",
        title="📊 Analysis (Simulated)"
    ))

    # Simula remediation
    console.print("\n[blue]3/4 RemediationAgent — generating patches (simulated)...[/blue]")
    for f in [x for x in findings if x.get("rule_id") in ("QSC-010", "QSC-030", "QSC-022")]:
        patch = execute_tool("generate_remediation_patch", {
            "file_path": f.get("file",""), "rule_id": f.get("rule_id",""), "code_snippet": f.get("code_snippet","")
        })
        console.print(f"  [green]✅[/green] Patch for {f.get('rule_id')}: {patch['patch'].get('explanation','')}")

    # Simula incident
    console.print("\n[blue]4/4 IncidentAgent — responding to hardcoded credential...[/blue]")
    inc = await mem.open_incident(
        title="Hardcoded credential in src/secrets.rs",
        description="API key found hardcoded in production code",
        severity="CRITICAL",
        agent="IncidentAgent",
    )
    alert = execute_tool("send_alert", {
        "severity": "INCIDENT",
        "title": f"[{inc.id}] Hardcoded credential detected",
        "message": "Rotate all production API keys immediately. Remove from codebase.",
        "details": {"incident_id": inc.id, "file": "src/secrets.rs", "line": 5}
    })
    await mem.resolve_incident(inc.id, "Alert sent, rotation instructions provided")

    snap = await mem.snapshot()
    console.print("\n")
    console.print(Panel(
        f"Total Findings:   {snap['total_findings']}\n"
        f"Active Incidents: {snap['active_incidents']}\n"
        f"Pending Patches:  {snap['pending_patches']}\n"
        f"Agent Actions:    {snap['agent_actions']}\n\n"
        "[dim]Configure ANTHROPIC_API_KEY para análise real com Claude[/dim]",
        title="✅ Demo Complete"
    ))


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qsec-agents",
        description="QSEC Multi-Agent Security System"
    )
    sub = p.add_subparsers(dest="command")

    # audit
    audit = sub.add_parser("audit", help="Full security audit (scan + analyze + remediate)")
    audit.add_argument("project", help="Project path")
    audit.add_argument("--auto-remediate", action="store_true", help="Apply Quick Win patches automatically")

    # monitor
    mon = sub.add_parser("monitor", help="Continuous monitoring")
    mon.add_argument("project", help="Project path to watch")
    mon.add_argument("--interval", type=int, default=30, help="Check interval in seconds")

    # incident
    inc = sub.add_parser("incident", help="Trigger incident response")
    inc.add_argument("type", choices=["key_compromise", "hardcoded_cred", "jwt_none", "vuln_dep"])
    inc.add_argument("--desc", required=True, help="Incident description")
    inc.add_argument("--file", default="", help="Affected file")
    inc.add_argument("--key-id", default="", help="Affected key ID")

    # supply
    sup = sub.add_parser("supply", help="Supply chain security pipeline")
    sup.add_argument("project", help="Project path")
    sup.add_argument("--artifacts", default="", help="Comma-separated artifact paths")
    sup.add_argument("--out-dir", default="./qsec-out")

    # keys
    keys = sub.add_parser("keys", help="Key lifecycle management")
    keys.add_argument("action", choices=["status", "rotate", "revoke"])
    keys.add_argument("--key-id", default="")
    keys.add_argument("--reason", default="")

    # demo
    sub.add_parser("demo", help="Run full demo (no API key required for simulation)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "audit":    cmd_audit,
        "monitor":  cmd_monitor,
        "incident": cmd_incident,
        "supply":   cmd_supply,
        "keys":     cmd_keys,
        "demo":     lambda _: cmd_demo(),
    }

    handler = dispatch.get(args.command)
    if handler:
        asyncio.run(handler(args))


if __name__ == "__main__":
    main()
