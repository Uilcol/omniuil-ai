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
