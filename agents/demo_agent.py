"""
OmniUil AI Agents — Demo Agent (Agente de Demonstração)
=========================================================
Terceiro agente especializado em executar demonstrações técnicas ao vivo.

Responsabilidades:
  - Executa scan no repositório do prospect
  - Calcula Quantum Posture Score
  - Gera Migration Intelligence
  - Explica cada finding com contexto técnico
  - Apresenta limitações reais com transparência total
  - Gera relatório HTML profissional para envio ao prospect
  - Tudo aguardando aprovação do fundador antes de enviar

Princípio: transparência ética > marketing. Um CISO técnico respeita
honestidade sobre limitações mais do que promessas exageradas.
"""
import json, os, subprocess, tempfile, time
from datetime import datetime, timezone
from groq import Groq
from config import GROQ_API_KEY, GROQ_MODEL, PRODUCT_CONTEXT
from db import init_db, add_pending

client = Groq(api_key=GROQ_API_KEY)
DEMO_AGENT_NAME = "Demo"

QSEC_BIN = os.path.expanduser(
    "~/QSEC/qsec-rust/target/release/qsec"
)

# ── Limitações conhecidas e honestas ─────────────────────────────────────────
KNOWN_LIMITATIONS = [
    {
        "title": "Taint analysis intra-arquivo apenas",
        "detail": "O OmniUil rastreia fluxo de dados dentro de um único arquivo. Vulnerabilidades que cruzam múltiplos arquivos (ex: parâmetro definido em config.py e usado em crypto.py) podem não ser detectadas.",
        "workaround": "Para cross-file taint, combine com revisão manual nos pontos de entrada identificados pelo scanner.",
        "roadmap": "Cross-file taint analysis está no roadmap v6.0."
    },
    {
        "title": "Falsos positivos em código de interoperabilidade",
        "detail": "Sistemas que precisam suportar RSA/ECDSA por compatibilidade com clientes legados serão sinalizados mesmo que a implementação seja intencional e controlada.",
        "workaround": "Use --exclude para diretórios de compatibilidade, ou adicione comentário # omniuil:ignore na linha específica.",
        "roadmap": "Anotações de supressão via comentário estão planejadas para v5.1."
    },
    {
        "title": "ML-KEM/ML-DSA em modo referência",
        "detail": "O engine PQC opera em modo de simulação/referência — detecta onde você DEVE migrar, mas não substitui automaticamente por código ML-KEM de produção.",
        "workaround": "O Migration Intelligence indica exatamente qual biblioteca PQC usar em cada substituição.",
        "roadmap": "Auto-remediate com código PQC real está no roadmap v5.5."
    },
    {
        "title": "Arquivos binários e código compilado",
        "detail": "O scanner analisa código-fonte. Bibliotecas já compiladas (.jar, .so, .dll) não são inspecionadas internamente.",
        "workaround": "Para análise de dependências compiladas, combine com o SBOM CycloneDX gerado pelo OmniUil.",
        "roadmap": "Análise de bytecode JVM está em avaliação para v6.0."
    },
]

def run_scan(repo_path: str, exclude_patterns: list = None) -> dict:
    """Executa o scan real e retorna findings + metadados."""
    if not os.path.exists(QSEC_BIN):
        return {"error": f"Binário não encontrado: {QSEC_BIN}", "findings": []}

    args = [QSEC_BIN, "scan", repo_path, "--format", "json"]
    if exclude_patterns:
        args += ["--exclude", ",".join(exclude_patterns)]

    try:
        start = time.time()
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=300)
        duration = time.time() - start

        findings = []
        if result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
                findings = parsed if isinstance(parsed, list) else parsed.get("findings", [])
            except json.JSONDecodeError:
                pass

        # Conta arquivos escaneados
        files_scanned = 0
        for line in result.stderr.split("\n"):
            if "arquivos" in line.lower() or "files" in line.lower():
                import re
                nums = re.findall(r"\d+", line)
                if nums:
                    files_scanned = int(nums[0])

        return {
            "findings": findings,
            "files_scanned": files_scanned,
            "duration_seconds": round(duration, 2),
            "stderr": result.stderr[:500],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout (>5 minutos)", "findings": []}
    except Exception as e:
        return {"error": str(e), "findings": []}

def explain_finding(finding: dict) -> str:
    """Gera explicação técnica detalhada de um finding específico."""
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": f"""Você é um especialista em segurança criptográfica pós-quântica.
Explique este finding de forma clara para um CISO ou CTO.
Seja técnico mas acessível. Máximo 150 palavras.
Inclua: por que é problema, impacto real, algoritmo PQC recomendado.
{PRODUCT_CONTEXT}"""},
            {"role": "user", "content": f"""Finding:
Regra: {finding.get("rule_id")}
Severidade: {finding.get("severity")}
Título: {finding.get("title")}
Arquivo: {finding.get("file", "").split("/")[-1]}
Linha: {finding.get("line")}
Snippet: {finding.get("snippet", "")[:200]}

Explique este finding com contexto de negócio e risco quântico."""}
        ],
        temperature=0.4, max_tokens=200
    )
    return resp.choices[0].message.content.strip()

def generate_demo_report(
    company: str,
    contact_name: str,
    repo_path: str,
    repo_url: str = "",
    exclude_patterns: list = None,
) -> dict:
    """
    Executa demonstração completa e gera relatório para aprovação.
    Retorna dict com action_id e resumo.
    """
    print(f"[{DEMO_AGENT_NAME}] Iniciando demo para {company}...")
    print(f"[{DEMO_AGENT_NAME}] Repositório: {repo_path}")

    # 1. Executa scan real
    print(f"[{DEMO_AGENT_NAME}] Executando scan...")
    scan_result = run_scan(repo_path, exclude_patterns)

    if "error" in scan_result:
        print(f"[{DEMO_AGENT_NAME}] Erro no scan: {scan_result['error']}")
        return {"error": scan_result["error"]}

    findings   = scan_result["findings"]
    duration   = scan_result["duration_seconds"]
    files      = scan_result["files_scanned"]

    print(f"[{DEMO_AGENT_NAME}] {len(findings)} findings em {duration}s")

    # 2. Calcula Quantum Posture Score
    from quantum_posture import calculate_quantum_posture
    posture = calculate_quantum_posture(findings, repo_path, files)
    print(f"[{DEMO_AGENT_NAME}] Quantum Posture Score: {posture.score}/100 — {posture.risk_level}")

    # 3. Migration Intelligence
    from migration_intelligence import generate_migration_plan
    plan = generate_migration_plan(findings, repo_path)
    print(f"[{DEMO_AGENT_NAME}] Plano: {plan.total_steps} etapas, {plan.executive_summary[:60]}...")

    # 4. Explica top 3 findings mais críticos
    top_findings = sorted(
        findings,
        key=lambda f: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(
            f.get("severity","LOW").upper(), 0),
        reverse=True
    )[:3]

    explained = []
    for f in top_findings:
        explanation = explain_finding(f)
        explained.append({
            "finding": f,
            "explanation": explanation,
        })
        time.sleep(1)  # respeita rate limit do Groq

    # 5. Gera resumo executivo personalizado
    print(f"[{DEMO_AGENT_NAME}] Gerando resumo executivo...")
    exec_resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": f"""Você é o Demo Agent do OmniUil AI.
Gere um resumo executivo de demonstração técnica.
Tom: profissional, transparente, técnico mas acessível.
Inclua pontos positivos E limitações honestas.
Máximo 250 palavras. Português formal."""},
            {"role": "user", "content": f"""Empresa: {company}
Contato: {contact_name}
Repositório: {repo_url or repo_path}
Findings: {len(findings)} ({posture.critical_findings} CRITICAL, {posture.high_findings} HIGH)
Quantum Posture Score: {posture.score}/100 — {posture.risk_level}
Top riscos: {json.dumps([r["category"] for r in posture.top_risks])}
Plano de migração: {plan.total_steps} etapas, {plan.total_effort_min}-{plan.total_effort_max}h, R${plan.total_cost_min:,}-R${plan.total_cost_max:,}
Deadline CNSA 2.0: {posture.months_to_deadline} meses

Gere resumo executivo da demonstração incluindo:
1. O que foi encontrado (findings reais)
2. Score e o que significa para o negócio
3. Plano resumido (primeiras 2 etapas)
4. 2-3 limitações honestas do scanner neste contexto
5. Próximos passos sugeridos"""}
        ],
        temperature=0.5, max_tokens=400
    )
    executive_summary = exec_resp.choices[0].message.content.strip()

    # 6. Gera relatório HTML profissional
    html_report = _build_html_report(
        company, contact_name, repo_url,
        findings, posture, plan, explained,
        executive_summary, duration, files
    )

    # 7. Monta e-mail com relatório para aprovação
    email_body = f"""Prezado(a) {contact_name},

Conforme combinado, segue o relatório da demonstração técnica do OmniUil AI v5.0 realizada no repositório {repo_url or repo_path}.

{executive_summary}

O relatório completo com todos os {len(findings)} findings, Quantum Posture Score ({posture.score}/100) e Plano de Migração detalhado está em anexo.

Estamos à disposição para esclarecer qualquer dúvida técnica e discutir os próximos passos.

Atenciosamente,
OmniUil AI — Segurança Criptográfica Pós-Quântica
github.com/Uilcol/omniuil-ai"""

    # 8. Cria ação pendente de aprovação
    import sys
    sys.path.insert(0, os.path.expanduser("~/QSEC/qsec-enterprise/api"))

    action_id = add_pending(
        agent=DEMO_AGENT_NAME,
        action_type="demo_report",
        subject=f"Relatório Demo OmniUil AI — {company} | Score {posture.score}/100",
        to_email="",  # preenchido pelo fundador na aprovação
        content=email_body,
        context=json.dumps({
            "company":         company,
            "contact":         contact_name,
            "repo":            repo_url or repo_path,
            "score":           posture.score,
            "risk_level":      posture.risk_level,
            "findings_total":  len(findings),
            "findings_critical": posture.critical_findings,
            "plan_steps":      plan.total_steps,
            "cost_min":        plan.total_cost_min,
            "cost_max":        plan.total_cost_max,
            "duration_s":      duration,
            "html_report":     html_report[:5000],
        })
    )

    print(f"[{DEMO_AGENT_NAME}] Relatório #{action_id} criado para aprovação no dashboard")
    return {
        "action_id":    action_id,
        "score":        posture.score,
        "risk_level":   posture.risk_level,
        "findings":     len(findings),
        "plan_steps":   plan.total_steps,
        "cost_range":   f"R${plan.total_cost_min:,}–R${plan.total_cost_max:,}",
        "duration":     duration,
    }

def _build_html_report(
    company, contact, repo_url,
    findings, posture, plan, explained,
    exec_summary, duration, files
) -> str:
    """Gera relatório HTML profissional para envio ao prospect."""
    risk_colors = {
        "CRITICAL":"#ff4444","HIGH":"#ffaa00",
        "MEDIUM":"#ffff00","LOW":"#00d4ff","MINIMAL":"#00e676"
    }
    score_color = risk_colors.get(posture.risk_level, "#8888ff")

    top_risks_html = "".join(
        f'<li><strong>{r["category"]}</strong> — {r["count"]} ocorrência(s), risco PQC: {r["pqc_risk"]}</li>'
        for r in posture.top_risks
    )

    steps_html = "".join(
        f'<tr><td><span class="badge-{s.priority.lower()}">{s.priority}</span></td>'
        f'<td>{s.title[:60]}</td><td>{s.deadline_date}</td>'
        f'<td>{s.effort_hours_min}-{s.effort_hours_max}h</td>'
        f'<td>R${s.cost_brl_min:,}-R${s.cost_brl_max:,}</td></tr>'
        for s in plan.steps
    )

    explained_html = "".join(
        f'<div class="finding-card sev-{f["finding"].get("severity","LOW").lower()}">'
        f'<div class="finding-header">'
        f'<span class="badge-sev">{f["finding"].get("severity")}</span>'
        f'<strong>{f["finding"].get("title")}</strong>'
        f'<code>{f["finding"].get("file","").split("/")[-1]}:{f["finding"].get("line")}</code>'
        f'</div><p>{f["explanation"]}</p></div>'
        for f in explained
    )

    limitations_html = "".join(
        f'<div class="limitation"><h4>⚠️ {l["title"]}</h4>'
        f'<p>{l["detail"]}</p>'
        f'<p><strong>Alternativa:</strong> {l["workaround"]}</p>'
        f'<p><em>Roadmap: {l["roadmap"]}</em></p></div>'
        for l in KNOWN_LIMITATIONS[:2]
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>OmniUil AI — Relatório de Demonstração — {company}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#020b14;color:#e0f0ff;margin:0;padding:0}}
.header{{background:#040d1a;border-bottom:3px solid #00d4ff;padding:2rem 3rem}}
.header h1{{color:#00d4ff;margin:0;font-size:1.5rem}}
.header p{{color:#4a9abb;margin:.25rem 0 0}}
.content{{max-width:1000px;margin:0 auto;padding:2rem 3rem}}
.score-box{{background:#07111e;border:2px solid {score_color};border-radius:12px;padding:2rem;text-align:center;margin:1.5rem 0}}
.score-num{{font-size:4rem;font-weight:700;color:{score_color}}}
.score-label{{color:{score_color};font-size:1.1rem;font-weight:600}}
.grid{{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:1rem;margin:1.5rem 0}}
.card{{background:#07111e;border:1px solid #1a3a5c;border-radius:8px;padding:1rem;text-align:center}}
.card-num{{font-size:2rem;font-weight:700;color:#00d4ff}}
.card-label{{font-size:.75rem;color:#4a9abb}}
.section{{margin:2rem 0}}
.section h2{{color:#00d4ff;border-bottom:1px solid #1a3a5c;padding-bottom:.5rem}}
.exec-summary{{background:#07111e;border-left:4px solid #00d4ff;padding:1.5rem;border-radius:0 8px 8px 0;line-height:1.7}}
table{{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.9rem}}
th{{background:#0a1628;padding:.75rem;text-align:left;color:#4a9abb;font-size:.75rem;letter-spacing:.1em}}
td{{padding:.75rem;border-bottom:1px solid #0a1628;vertical-align:top}}
.badge-immediate{{background:#ff444422;color:#ff4444;border:1px solid #ff444444;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700}}
.badge-short_term{{background:#ffaa0022;color:#ffaa00;border:1px solid #ffaa0044;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700}}
.badge-medium_term{{background:#ffff0022;color:#ffff00;border:1px solid #ffff0044;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700}}
.badge-long_term{{background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff44;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700}}
.badge-sev{{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:700;margin-right:.5rem;background:#ff444422;color:#ff4444;border:1px solid #ff444444}}
.finding-card{{background:#07111e;border:1px solid #1a3a5c;border-radius:8px;padding:1.25rem;margin:.75rem 0}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;flex-wrap:wrap}}
.finding-header code{{background:#040d1a;padding:2px 8px;border-radius:4px;font-size:.8rem;color:#4a9abb}}
.sev-critical{{border-left:3px solid #ff4444}}
.sev-high{{border-left:3px solid #ffaa00}}
.limitation{{background:#07111e;border:1px solid #ffaa0044;border-radius:8px;padding:1.25rem;margin:.75rem 0}}
.limitation h4{{color:#ffaa00;margin:0 0 .5rem}}
.limitation p{{margin:.5rem 0;font-size:.9rem;line-height:1.6}}
.footer{{background:#040d1a;border-top:1px solid #1a3a5c;padding:1.5rem 3rem;text-align:center;color:#4a6a8a;font-size:.8rem;margin-top:3rem}}
</style></head><body>
<div class="header">
  <h1>⚡ OmniUil AI v5.0 — Relatório de Demonstração</h1>
  <p>Cliente: {company} | Contato: {contact} | Repositório: {repo_url or "local"}</p>
  <p>Gerado em: {datetime.now().strftime("%d/%m/%Y %H:%M")} | {files} arquivos em {duration}s</p>
</div>
<div class="content">
  <div class="score-box">
    <div class="score-num">{posture.score}<span style="font-size:2rem">/100</span></div>
    <div class="score-label">QUANTUM POSTURE — {posture.risk_level}</div>
    <p style="color:#8aaa;margin:.5rem 0 0">{posture.recommendation}</p>
    <p style="color:#ff4444;font-size:.85rem">⏰ CNSA 2.0: {posture.months_to_deadline} meses — {posture.deadline_urgency}</p>
  </div>

  <div class="grid">
    <div class="card"><div class="card-num" style="color:#ff4444">{posture.critical_findings}</div><div class="card-label">CRITICAL</div></div>
    <div class="card"><div class="card-num" style="color:#ffaa00">{posture.high_findings}</div><div class="card-label">HIGH</div></div>
    <div class="card"><div class="card-num">{len(findings)}</div><div class="card-label">TOTAL</div></div>
    <div class="card"><div class="card-num" style="color:#00e676">{plan.total_steps}</div><div class="card-label">ETAPAS</div></div>
  </div>

  <div class="section">
    <h2>Resumo Executivo</h2>
    <div class="exec-summary">{exec_summary.replace(chr(10),"<br>")}</div>
  </div>

  <div class="section">
    <h2>Principais Riscos Identificados</h2>
    <ul style="line-height:2">{top_risks_html}</ul>
  </div>

  <div class="section">
    <h2>Top 3 Findings — Explicação Técnica</h2>
    {explained_html}
  </div>

  <div class="section">
    <h2>Plano de Migração PQC</h2>
    <p style="color:#4a9abb;margin-bottom:1rem">{plan.executive_summary}</p>
    <table>
      <thead><tr><th>Prioridade</th><th>Ação</th><th>Prazo</th><th>Esforço</th><th>Custo</th></tr></thead>
      <tbody>{steps_html}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>⚠️ Transparência — Limitações Conhecidas</h2>
    <p style="color:#8aaa">O OmniUil AI é honesto sobre o que detecta e o que não detecta.</p>
    {limitations_html}
  </div>

  <div class="section" style="background:#07111e;border:1px solid #00e67633;border-radius:8px;padding:1.5rem">
    <h2 style="color:#00e676">Próximos Passos</h2>
    <ol style="line-height:2.2">
      <li>Revisar os {posture.critical_findings} findings CRITICAL com o time de engenharia</li>
      <li>Definir responsável pelo plano de migração PQC</li>
      <li>Selecionar plano OmniUil AI (Starter / Pro / Enterprise) para monitoramento contínuo</li>
      <li>Configurar Crypto Drift para detectar regressões em PRs futuros</li>
    </ol>
  </div>
</div>
<div class="footer">
  OmniUil AI v5.0 — github.com/Uilcol/omniuil-ai<br>
  Deploy locally. Analyze privately. Detect legacy cryptography. Prepare for the post-quantum era.
</div>
</body></html>"""

if __name__ == "__main__":
    # Teste com WebGoat (já clonado em /tmp/webgoat)
    init_db()
    import sys
    sys.path.insert(0, os.path.expanduser("~/QSEC/qsec-enterprise/api"))
    result = generate_demo_report(
        company="OWASP WebGoat (Demonstração)",
        contact_name="Time de Segurança",
        repo_path="/tmp/webgoat",
        repo_url="https://github.com/WebGoat/WebGoat",
        exclude_patterns=["**/test/**","**/tests/**"]
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
