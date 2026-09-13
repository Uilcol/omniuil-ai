"""
OmniUil AI Agents — Vulcan (Agente Técnico)
Responsável por: suporte técnico, documentação, GitHub issues
SEM acesso à internet — usa apenas GitHub e docs locais
"""
import json, os
from groq import Groq
from config import GROQ_API_KEY, GROQ_MODEL, PRODUCT_CONTEXT, VULCAN_NAME, GITHUB_TOKEN
from db import add_pending, log_conversation
from github_client import get_issues, get_readme, get_latest_release, get_recent_commits

client = Groq(api_key=GROQ_API_KEY)

# Carrega documentação local
def load_local_docs() -> str:
    docs = []
    paths = [
        os.path.expanduser("~/QSEC/README.md"),
        os.path.expanduser("~/QSEC/CASE_STUDY.md"),
    ]
    for p in paths:
        if os.path.exists(p):
            content = open(p).read()[:2000]
            docs.append(f"=== {os.path.basename(p)} ===\n{content}")
    return "\n\n".join(docs)

LOCAL_DOCS = load_local_docs()

SYSTEM_PROMPT = f"""Você é Vulcan, agente técnico do OmniUil AI.
Seu papel: suporte técnico, resolução de problemas, documentação.
SEM acesso à internet — use apenas documentação local e GitHub do projeto.
Seja preciso, técnico e detalhado. Fale português brasileiro.
NUNCA discuta preços ou contratos — redirecione para Mercury (agente comercial).

{PRODUCT_CONTEXT}

Documentação local:
{LOCAL_DOCS[:1000]}

Regras:
1. Para problemas de instalação: guie passo a passo
2. Para bugs: peça logs e versão do sistema
3. Para dúvidas de uso: cite exemplos reais do produto
4. Para perguntas de preço/contrato: "Para isso, fale com nossa equipe comercial"
5. Sempre verifique se há issues abertas no GitHub relacionadas ao problema
"""

def analyze_technical_question(question: str, context: str = "") -> str:
    """Gera resposta técnica para uma pergunta."""
    # Busca issues relacionadas no GitHub
    github_context = ""
    if GITHUB_TOKEN:
        issues = get_issues(state="open", limit=5)
        if issues:
            github_context = "Issues abertas no GitHub:\n" + "\n".join(
                [f"#{i['number']}: {i['title']}" for i in issues])

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":f"""Pergunta técnica recebida:
{question}

Contexto adicional: {context}

{github_context}

Forneça uma resposta técnica completa e precisa.
Se necessário instalar/configurar, forneça comandos exatos."""}
        ],
        temperature=0.3, max_tokens=600)
    return resp.choices[0].message.content.strip()

def process_technical_email(from_addr: str, subject: str, body: str) -> int:
    """Processa e-mail técnico e gera rascunho de resposta."""
    print(f"[{VULCAN_NAME}] Processando questão técnica de: {from_addr[:30]}")
    response = analyze_technical_question(body, f"Assunto: {subject}")
    action_id = add_pending(
        agent=VULCAN_NAME,
        action_type="send_email",
        subject=f"Re: {subject} [Suporte Técnico OmniUil AI]",
        to_email=from_addr,
        content=response,
        context=json.dumps({"original_subject":subject,"original_body":body[:500]})
    )
    log_conversation(from_addr, "received_technical", subject, body[:1000], VULCAN_NAME)
    print(f"[{VULCAN_NAME}] Rascunho técnico #{action_id} criado para aprovação")
    return action_id

def generate_faq() -> str:
    """Gera FAQ atualizado baseado nas issues do GitHub."""
    issues = get_issues(state="closed", limit=10) if GITHUB_TOKEN else []
    readme = get_readme() if GITHUB_TOKEN else LOCAL_DOCS[:1000]

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":f"""Gere um FAQ técnico do OmniUil AI com 10 perguntas e respostas.
Base: documentação do produto e issues resolvidas.
Issues resolvidas: {json.dumps(issues[:5])}
Foque em: instalação, configuração, uso do CLI, regras YAML, integração CI/CD."""}
        ],
        temperature=0.4, max_tokens=1000)
    content = resp.choices[0].message.content.strip()
    action_id = add_pending(
        agent=VULCAN_NAME,
        action_type="update_docs",
        subject="FAQ Técnico Atualizado",
        to_email="",
        content=content,
        context=json.dumps({"source":"github_issues"})
    )
    print(f"[{VULCAN_NAME}] FAQ #{action_id} gerado para aprovação")
    return content

def check_github_issues() -> list:
    """Verifica novas issues no GitHub e sugere respostas."""
    if not GITHUB_TOKEN:
        print(f"[{VULCAN_NAME}] GitHub token não configurado — pulando verificação")
        return []
    issues = get_issues(state="open", limit=5)
    actions = []
    for issue in issues:
        response = analyze_technical_question(
            f"Issue #{issue['number']}: {issue['title']}\n{issue['body']}",
            "Issue aberta no GitHub"
        )
        action_id = add_pending(
            agent=VULCAN_NAME,
            action_type="github_reply",
            subject=f"Issue #{issue['number']}: {issue['title']}",
            to_email="",
            content=response,
            context=json.dumps({"issue_number":issue["number"]})
        )
        actions.append(action_id)
        print(f"[{VULCAN_NAME}] Resposta para Issue #{issue['number']} criada para aprovação")
    return actions

if __name__ == "__main__":
    print(f"[{VULCAN_NAME}] Verificando issues no GitHub...")
    check_github_issues()


# ── Módulo de fechamento de contrato ─────────────────────────────────────────
PRICING = {
    "starter":    {"monthly": 450,   "annual": 4500,   "repos": 5,   "agents": 2},
    "pro":        {"monthly": 1450,  "annual": 14500,  "repos": -1,  "agents": 5},
    "enterprise": {"monthly": None,  "annual": None,   "repos": -1,  "agents": 5},
}

CONTRACT_SYSTEM = f"""Você é Vulcan, agente técnico do OmniUil AI v5.0.
Quando um prospect quer fechar contrato, você:
1. Identifica o plano mais adequado ao perfil dele
2. Calcula o valor (mensal ou anual com 17%% desconto)
3. Gera proposta formal em português para aprovação do fundador
4. NUNCA envia contrato sem aprovação explícita do fundador
5. Para Enterprise: sempre indica que o valor é sob consulta

Tabela de preços:
- Starter: R$ 450/mês ou R$ 4.500/ano (17%% desconto) — até 5 repos, 2 agentes IA
- Pro: R$ 1.450/mês ou R$ 14.500/ano (17%% desconto) — repos ilimitados, 5 agentes IA
- Enterprise: sob consulta — inclui SLA, suporte dedicado, on-premise assistido

{PRODUCT_CONTEXT}
"""

def generate_contract_proposal(
    from_email: str,
    company: str,
    contact_name: str,
    interest: str,
    repos_count: int = 0,
    team_size: int = 0,
    billing: str = "monthly"
) -> int:
    """
    Gera proposta de contrato para aprovação do fundador.
    Retorna o action_id da proposta pendente.
    """
    # Determina plano recomendado
    if repos_count <= 5 and team_size <= 10:
        recommended_plan = "starter"
    elif team_size > 50 or repos_count == -1:
        recommended_plan = "enterprise"
    else:
        recommended_plan = "pro"

    pricing = PRICING[recommended_plan]
    if billing == "annual" and pricing["monthly"]:
        valor = pricing["annual"]
        billing_str = f"R$ {valor:,}/ano (equivale a R$ {valor//12:,}/mês — 17% de desconto)"
    elif pricing["monthly"]:
        valor = pricing["monthly"]
        billing_str = f"R$ {valor:,}/mês"
    else:
        billing_str = "Sob consulta (Enterprise)"

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": CONTRACT_SYSTEM},
            {"role": "user", "content": f"""Gere proposta de contrato formal para:

Empresa: {company}
Contato: {contact_name}
E-mail: {from_email}
Interesse declarado: {interest}
Repositórios estimados: {repos_count if repos_count > 0 else 'não informado'}
Tamanho do time: {team_size if team_size > 0 else 'não informado'}

Plano recomendado: {recommended_plan.upper()}
Valor: {billing_str}

A proposta deve incluir:
1. Agradecimento pelo interesse
2. Resumo do que está incluído no plano {recommended_plan}
3. Valor e condições de pagamento
4. Próximos passos (assinatura, emissão de licença, onboarding)
5. Validade da proposta: 15 dias

Máximo 300 palavras. Formal, profissional."""}
        ],
        temperature=0.4,
        max_tokens=500
    )

    proposal = resp.choices[0].message.content.strip()
    subject = f"Proposta OmniUil AI — {company} — Plano {recommended_plan.upper()}"

    action_id = add_pending(
        agent=VULCAN_NAME,
        action_type="contract_proposal",
        subject=subject,
        to_email=from_email,
        content=proposal,
        context=json.dumps({
            "company": company,
            "contact": contact_name,
            "plan": recommended_plan,
            "billing": billing,
            "billing_str": billing_str,
            "repos": repos_count,
            "team_size": team_size,
        })
    )
    print(f"[{VULCAN_NAME}] Proposta #{action_id} gerada para {company} — {recommended_plan} {billing_str}")
    return action_id


def handle_contract_intent(from_email: str, subject: str, body: str) -> int:
    """
    Detecta intenção de fechar contrato no e-mail e gera proposta.
    """
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": "Extraia dados de e-mail de interesse em contrato. Retorne APENAS JSON."},
            {"role": "user", "content": f"""E-mail:
De: {from_email}
Assunto: {subject}
Corpo: {body[:600]}

Extraia:
{{
  "wants_contract": true/false,
  "company": "nome da empresa",
  "contact_name": "nome do contato",
  "repos_count": 0,
  "team_size": 0,
  "prefers_annual": false,
  "interest_summary": "resumo do interesse"
}}"""}
        ],
        temperature=0.1,
        max_tokens=200
    )
    import json
    try:
        data = json.loads(resp.choices[0].message.content.strip())
    except:
        data = {"wants_contract": False}

    if not data.get("wants_contract"):
        return 0

    billing = "annual" if data.get("prefers_annual") else "monthly"
    return generate_contract_proposal(
        from_email=from_email,
        company=data.get("company", "Empresa"),
        contact_name=data.get("contact_name", ""),
        interest=data.get("interest_summary", ""),
        repos_count=data.get("repos_count", 0),
        team_size=data.get("team_size", 0),
        billing=billing,
    )
