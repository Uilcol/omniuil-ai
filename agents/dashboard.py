"""
OmniUil AI Agents — Dashboard de Aprovação
Interface web local para aprovar/rejeitar ações dos agentes
"""
from flask import Flask, render_template_string, request, jsonify, redirect
from db import get_pending, approve_action, reject_action, get_leads, init_db
from gmail_client import send_email
import json

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width">
<title>OmniUil AI — Agentes</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#020b14;color:#e0f0ff;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
nav{background:#040d1a;border-bottom:1px solid #1a3a5c;padding:1rem 2rem;display:flex;align-items:center;gap:2rem}
nav h1{color:#00d4ff;font-size:1.1rem;letter-spacing:.1em}
nav a{color:#4a9abb;text-decoration:none;font-size:.85rem}
nav a:hover{color:#00d4ff}
.badge{background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff44;padding:2px 8px;border-radius:20px;font-size:.75rem}
.badge-red{background:#ff444422;color:#ff4444;border-color:#ff444444}
main{padding:2rem;max-width:1200px;margin:0 auto}
.section-title{font-size:.7rem;color:#4a9abb;letter-spacing:.2em;margin-bottom:1rem}
.card{background:#07111e;border:1px solid #1a3a5c;border-radius:10px;padding:1.5rem;margin-bottom:1rem}
.card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1rem}
.agent-badge{font-size:.75rem;font-weight:700;padding:3px 10px;border-radius:20px}
.mercury{background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff44}
.vulcan{background:#ff990022;color:#ff9900;border:1px solid #ff990044}
.subject{font-weight:600;font-size:.95rem;margin-bottom:.25rem}
.to{font-size:.8rem;color:#4a9abb}
.content{background:#040d1a;border:1px solid #0a1628;border-radius:6px;padding:1rem;font-size:.85rem;line-height:1.6;white-space:pre-wrap;margin:1rem 0;max-height:200px;overflow-y:auto}
.actions{display:flex;gap:.75rem}
.btn{padding:.5rem 1.2rem;border-radius:6px;font-weight:600;font-size:.85rem;cursor:pointer;border:none}
.btn-approve{background:#00e67622;color:#00e676;border:1px solid #00e67644}
.btn-approve:hover{background:#00e67633}
.btn-reject{background:#ff444422;color:#ff4444;border:1px solid #ff444444}
.btn-reject:hover{background:#ff444433}
.btn-edit{background:#ffaa0022;color:#ffaa00;border:1px solid #ffaa0044}
.empty{text-align:center;padding:3rem;color:#4a6a8a}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}
.stat{background:#07111e;border:1px solid #1a3a5c;border-radius:8px;padding:1rem;text-align:center}
.stat-num{font-size:1.8rem;font-weight:700;color:#00d4ff}
.stat-label{font-size:.7rem;color:#4a9abb;margin-top:4px}
.context{font-size:.75rem;color:#4a6a8a;margin-top:.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{padding:.6rem 1rem;text-align:left;color:#4a9abb;font-size:.7rem;letter-spacing:.1em;border-bottom:1px solid #1a3a5c}
td{padding:.6rem 1rem;border-bottom:1px solid #0a1628}
.refresh{float:right;font-size:.75rem;color:#4a6a8a}
</style>
</head>
<body>
<nav>
  <h1>⚡ OMNIUIL AI AGENTS</h1>
  <a href="/">📋 Aprovações</a>
  <a href="/leads">👥 Leads</a>
  <a href="/run/mercury">▶ Rodar Mercury</a>
  <a href="/run/vulcan">▶ Rodar Vulcan</a>
  <a href="/generate/post">✍ Gerar Post LinkedIn</a>
  <a href="/generate/faq">📄 Gerar FAQ</a>
  <a href="/prospect/all">🎯 Prospectar Clientes</a>
  <a href="/prospect/matera">📧 Matera</a>
  <a href="/prospect/iti">📧 ITI</a>
  <a href="/prospect/serpro">📧 SERPRO</a>
  <a href="/prospect/btg">📧 BTG</a>
  <span class="badge">{{ pending_count }} pendentes</span>
</nav>
<main>
  <div class="stats">
    <div class="stat"><div class="stat-num">{{ pending_count }}</div><div class="stat-label">AGUARDANDO APROVAÇÃO</div></div>
    <div class="stat"><div class="stat-num">{{ lead_count }}</div><div class="stat-label">LEADS CAPTURADOS</div></div>
    <div class="stat"><div class="stat-num">{{ approved_count }}</div><div class="stat-label">AÇÕES APROVADAS</div></div>
  </div>

  <div class="section-title">// AÇÕES PENDENTES DE APROVAÇÃO</div>

  {% if not actions %}
  <div class="card empty">
    <div style="font-size:2rem;margin-bottom:.5rem">✅</div>
    Nenhuma ação pendente. Os agentes estão prontos.
  </div>
  {% endif %}

  {% for a in actions %}
  <div class="card">
    <div class="card-header">
      <div>
        <span class="agent-badge {{ a.agent.lower() }}">{{ a.agent }}</span>
        <span style="font-size:.75rem;color:#4a6a8a;margin-left:.5rem">{{ a.action_type }}</span>
        <div class="subject" style="margin-top:.5rem">{{ a.subject }}</div>
        {% if a.to_email %}<div class="to">Para: {{ a.to_email }}</div>{% endif %}
      </div>
      <div style="font-size:.7rem;color:#4a6a8a">{{ a.created_at }}</div>
    </div>

    <form method="post" action="/edit/{{ a.id }}">
      <textarea name="content" style="width:100%;background:#040d1a;border:1px solid #1a3a5c;border-radius:6px;color:#e0f0ff;padding:1rem;font-size:.85rem;line-height:1.6;height:150px;resize:vertical;font-family:inherit">{{ a.content }}</textarea>
      <div class="actions" style="margin-top:.75rem">
        <button type="submit" name="action" value="approve" class="btn btn-approve">✅ Aprovar e Enviar</button>
        <button type="submit" name="action" value="reject" class="btn btn-reject">❌ Rejeitar</button>
        <button type="submit" name="action" value="edit" class="btn btn-edit">✏️ Salvar Edição</button>
      </div>
    </form>
    {% if a.context %}
    <div class="context">Contexto: {{ a.context[:200] }}</div>
    {% endif %}
  </div>
  {% endfor %}

  {% if leads %}
  <div class="section-title" style="margin-top:2rem">// LEADS CAPTURADOS</div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>Nome</th><th>Empresa</th><th>Cargo</th><th>Interesse</th><th>Status</th></tr></thead>
      <tbody>
      {% for l in leads %}
      <tr>
        <td>{{ l.name or "—" }}</td>
        <td>{{ l.company or "—" }}</td>
        <td>{{ l.cargo or "—" }}</td>
        <td style="font-size:.78rem;color:#8aaa">{{ l.interest or "—" }}</td>
        <td><span class="badge">{{ l.status }}</span></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</main>
</body>
</html>"""

@app.route("/")
def index():
    from db import get_conn
    actions = get_pending()
    leads   = get_leads()
    conn    = get_conn()
    approved_count = conn.execute("SELECT COUNT(*) FROM pending_actions WHERE status='approved'").fetchone()[0]
    conn.close()
    return render_template_string(HTML,
        actions=actions, leads=leads,
        pending_count=len(actions),
        lead_count=len(leads),
        approved_count=approved_count)

@app.route("/edit/<int:action_id>", methods=["POST"])
def edit_action(action_id):
    action  = request.form.get("action")
    content = request.form.get("content","")
    from db import get_conn
    conn = get_conn()
    row  = conn.execute("SELECT * FROM pending_actions WHERE id=?", (action_id,)).fetchone()
    conn.close()
    if not row:
        return redirect("/")
    if action == "approve":
        # Envia o e-mail se for send_email
        if row["action_type"] == "send_email" and row["to_email"]:
            try:
                send_email(row["to_email"], row["subject"], content)
                from db import log_conversation
                log_conversation(row["to_email"], "sent", row["subject"], content, row["agent"])
                print(f"✅ E-mail enviado para {row['to_email']}")
            except Exception as e:
                print(f"❌ Erro ao enviar e-mail: {e}")
        approve_action(action_id)
    elif action == "reject":
        reject_action(action_id)
    elif action == "edit":
        conn = get_conn()
        conn.execute("UPDATE pending_actions SET content=? WHERE id=?", (content, action_id))
        conn.commit()
        conn.close()
    return redirect("/")

@app.route("/leads")
def leads_page():
    leads = get_leads()
    return jsonify(leads)

@app.route("/run/mercury")
def run_mercury():
    from mercury import process_inbox
    count = process_inbox()
    return redirect(f"/?ran=mercury&count={count}")

@app.route("/run/vulcan")
def run_vulcan():
    from vulcan import check_github_issues
    actions = check_github_issues()
    return redirect(f"/?ran=vulcan&count={len(actions)}")

@app.route("/generate/post")
def gen_post():
    from mercury import generate_linkedin_post
    topic = request.args.get("topic", "Segurança criptográfica pós-quântica em 2026")
    generate_linkedin_post(topic)
    return redirect("/")

@app.route("/generate/faq")
def gen_faq():
    from vulcan import generate_faq
    generate_faq()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    from config import DASHBOARD_PORT
    print(f"\n🚀 Dashboard OmniUil AI Agents rodando em http://localhost:{DASHBOARD_PORT}")
    print("   Mercury (Comercial) + Vulcan (Técnico) prontos para aprovação")
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False)
