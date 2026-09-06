"""
OmniUil AI Agents — Mercury (Agente Comercial)
Responsável por: e-mails, leads, contratos, divulgação
NUNCA age sem aprovação do fundador
"""
import json, re
from groq import Groq
from config import GROQ_API_KEY, GROQ_MODEL, PRODUCT_CONTEXT, MERCURY_NAME
from db import add_pending, upsert_lead, log_conversation
from gmail_client import get_unread_emails, mark_as_read

client = Groq(api_key=GROQ_API_KEY)

SYSTEM_PROMPT = f"""Você é Mercury, agente comercial do OmniUil AI.
Seu papel: rascunhar respostas comerciais, identificar leads, sugerir follow-ups.
NUNCA envie e-mails sozinho — sempre gere rascunho para aprovação do fundador.
Seja profissional, direto e técnico. Fale português brasileiro.
Tom: confiante, especialista em segurança PQC, sem exageros de marketing.

{PRODUCT_CONTEXT}

Regras:
1. Sempre identifique se o contato é lead quente (CISO, CTO, banco, fintech, govtech)
2. Para perguntas técnicas avançadas: informe que o time técnico (Vulcan) responderá
3. Nunca invente funcionalidades — use apenas o contexto do produto acima
4. Para propostas de preço: diga "entre em contato para proposta personalizada"
5. Sempre termine com call-to-action claro
"""

def classify_lead(email_from: str, subject: str, body: str) -> dict:
    """Classifica se o e-mail é lead quente e extrai dados."""
    prompt = f"""Analise este e-mail e extraia em JSON:
{{
  "is_lead": true/false,
  "temperature": "hot/warm/cold",
  "name": "nome do remetente ou vazio",
  "company": "empresa ou vazio",
  "cargo": "cargo ou vazio",
  "interest": "resumo do interesse em 1 frase",
  "needs_technical": true/false
}}

De: {email_from}
Assunto: {subject}
Corpo: {body[:500]}

Retorne APENAS o JSON, sem explicação."""

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role":"system","content":"Você extrai dados de e-mails em JSON."},
                  {"role":"user","content":prompt}],
        temperature=0.1, max_tokens=200)
    try:
        return json.loads(resp.choices[0].message.content.strip())
    except:
        return {"is_lead":False,"temperature":"cold","name":"","company":"","cargo":"","interest":"","needs_technical":False}

def draft_response(email_from: str, subject: str, body: str, lead_info: dict) -> str:
    """Gera rascunho de resposta comercial."""
    context = f"Lead quente: {lead_info.get('temperature')} | Empresa: {lead_info.get('company','?')} | Cargo: {lead_info.get('cargo','?')}"

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":f"""Contexto do lead: {context}

E-mail recebido:
De: {email_from}
Assunto: {subject}
Mensagem: {body[:800]}

Escreva uma resposta profissional em português. Máximo 200 palavras.
Comece com saudação personalizada pelo nome se disponível."""}
        ],
        temperature=0.7, max_tokens=400)
    return resp.choices[0].message.content.strip()

def draft_followup(lead: dict) -> str:
    """Gera follow-up para lead sem resposta."""
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":f"""Gere um follow-up curto (máximo 100 palavras) para:
Nome: {lead.get('name','')}
Empresa: {lead.get('company','')}
Interesse: {lead.get('interest','')}
Contexto: não respondeu em 48h ao nosso e-mail inicial sobre OmniUil AI."""}
        ],
        temperature=0.7, max_tokens=200)
    return resp.choices[0].message.content.strip()

def process_inbox():
    """Lê caixa de entrada e gera rascunhos para aprovação."""
    print(f"[{MERCURY_NAME}] Verificando caixa de entrada...")
    emails = get_unread_emails(max_results=10)
    processed = 0

    for email in emails:
        from_addr = email["from"]
        subject   = email["subject"]
        body      = email["body"]

        # Classifica o lead
        lead_info = classify_lead(from_addr, subject, body)

        # Salva lead no banco se relevante
        if lead_info.get("is_lead"):
            email_clean = re.findall(r"[\w.+-]+@[\w-]+\.\w+", from_addr)
            email_clean = email_clean[0] if email_clean else from_addr
            upsert_lead(
                email=email_clean,
                name=lead_info.get("name",""),
                company=lead_info.get("company",""),
                cargo=lead_info.get("cargo",""),
                interest=lead_info.get("interest","")
            )

        # Gera rascunho de resposta
        draft = draft_response(from_addr, subject, body, lead_info)

        # Registra como ação pendente (aguarda aprovação)
        action_id = add_pending(
            agent=MERCURY_NAME,
            action_type="send_email",
            subject=f"Re: {subject}",
            to_email=from_addr,
            content=draft,
            context=json.dumps({
                "original_id": email["id"],
                "lead_info": lead_info,
                "original_subject": subject,
                "original_body": body[:500]
            })
        )

        # Log da conversa recebida
        log_conversation(from_addr, "received", subject, body[:1000], MERCURY_NAME)

        # Marca como lido para não processar de novo
        mark_as_read(email["id"])

        temp = lead_info.get("temperature","cold")
        print(f"[{MERCURY_NAME}] Rascunho #{action_id} criado | Lead: {temp} | De: {from_addr[:30]}")
        processed += 1

    if processed == 0:
        print(f"[{MERCURY_NAME}] Nenhum e-mail novo na caixa de entrada.")
    return processed

def generate_linkedin_post(topic: str) -> str:
    """Gera rascunho de post para LinkedIn."""
    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role":"system","content":SYSTEM_PROMPT},
            {"role":"user","content":f"""Crie um post profissional para LinkedIn sobre OmniUil AI.
Tema: {topic}
Máximo 300 palavras. Use dados reais do produto.
Inclua hashtags relevantes ao final.
Tom técnico mas acessível para CISO e CTO."""}
        ],
        temperature=0.8, max_tokens=500)
    content = resp.choices[0].message.content.strip()
    action_id = add_pending(
        agent=MERCURY_NAME,
        action_type="linkedin_post",
        subject=f"Post LinkedIn: {topic}",
        to_email="",
        content=content,
        context=json.dumps({"topic":topic})
    )
    print(f"[{MERCURY_NAME}] Post LinkedIn #{action_id} criado para aprovação")
    return content

if __name__ == "__main__":
    process_inbox()
