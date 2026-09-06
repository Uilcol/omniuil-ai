"""
OmniUil AI Agents — Módulo de Prospecção
Gera e-mails personalizados de divulgação para prospects estratégicos
com resultados reais de scan e proposta de valor específica por setor
"""
from groq import Groq
import os, json
from db import add_pending
from config import GROQ_API_KEY, GROQ_MODEL, PRODUCT_CONTEXT, MERCURY_NAME

client = Groq(api_key=GROQ_API_KEY)

# ── Prospects estratégicos com contexto específico ────────────────────────────
PROSPECTS = {
    "matera": {
        "empresa": "Matera Sistemas",
        "contato": "Carlos Netto",
        "cargo": "CEO e Cofundador",
        "email": "carlos.netto@matera.com",
        "setor": "Fintech / Core Banking / Pix",
        "contexto": """
        - Matera anunciou plano estratégico de adequação aos padrões PQC até 2029
        - Atuam em core banking, Pix e meios de pagamento
        - Dependem fortemente de RSA e ECDSA em autenticação e comunicação
        - O Pix exige conformidade com CNSA 2.0 obrigatória em 2027
        - Têm equipes Java/Spring Security — exatamente onde o OmniUil detectou
          437 vulnerabilidades CRITICAL em RSA e JWT no Spring Security oficial
        """,
        "resultado_relevante": "437 findings CRITICAL no Spring Security (RSA, JWT)",
        "urgencia": "CNSA 2.0 obrigatório em 2027 para sistemas Pix"
    },
    "iti": {
        "empresa": "Instituto Nacional de Tecnologia da Informação (ITI)",
        "contato": "Diretoria de Infraestrutura de Chaves Públicas",
        "cargo": "Diretor",
        "email": "iti@iti.gov.br",
        "setor": "Governo / ICP-Brasil / Certificação Digital",
        "contexto": """
        - ITI é responsável pela ICP-Brasil — infraestrutura de chaves públicas nacional
        - Todos os certificados digitais brasileiros dependem de RSA e ECDSA
        - O ITI precisa avaliar os riscos da computação quântica para a cadeia de confiança
        - Lei 14.063/2020 e a ANPD exigem atualização dos padrões criptográficos
        - São o órgão mais impactado pela transição PQC no Brasil
        """,
        "resultado_relevante": "RSA e ECDSA identificados como base de 100% dos certificados ICP-Brasil",
        "urgencia": "Risco sistêmico para toda a cadeia de confiança digital brasileira"
    },
    "serpro": {
        "empresa": "SERPRO — Serviço Federal de Processamento de Dados",
        "contato": "Diretoria de Segurança da Informação",
        "cargo": "Diretor de Segurança",
        "email": "seg@serpro.gov.br",
        "setor": "Governo / Dados fiscais / CPF / Receita Federal",
        "contexto": """
        - SERPRO processa dados de 200 milhões de brasileiros (CPF, CNPJ, IR)
        - Infraestrutura crítica nacional com múltiplos sistemas legados Java
        - Harvest Now Decrypt Later é uma ameaça real para dados fiscais históricos
        - Pressão regulatória da ANPD e do TCU por conformidade
        - Sistemas de autenticação gov.br dependem de algoritmos vulneráveis
        """,
        "resultado_relevante": "443 findings em Keycloak (SSO usado pelo gov.br) — RSA como provider padrão",
        "urgencia": "Dados fiscais históricos em risco de decriptação retroativa"
    },
    "btg": {
        "empresa": "BTG Pactual",
        "contato": "Diretoria de Tecnologia",
        "cargo": "CTO",
        "email": "ti@btgpactual.com",
        "setor": "Banco de Investimento / Asset Management",
        "contexto": """
        - BTG Pactual é o maior banco de investimento da América Latina
        - Opera com correspondentes internacionais que já exigem CNSA 2.0
        - Sistemas de trading e custódia dependem de RSA para comunicação segura
        - Regulação do BACEN exige atualização para padrões NIST pós-quânticos
        - Dados de operações financeiras históricas em risco de exposição futura
        """,
        "resultado_relevante": "RSA-2048 identificado como padrão em Spring Security e Keycloak — ambos usados por fintechs",
        "urgencia": "Correspondentes internacionais já exigem CNSA 2.0 em contratos"
    }
}

EMAIL_SYSTEM = f"""Você é Mercury, agente comercial sênior do OmniUil AI.
Redija e-mails de prospecção B2B de altíssima qualidade para CISOs, CTOs e diretores.
Tom: técnico, direto, confiante. Sem marketing genérico. Sem exageros.
Mostre que você conhece profundamente o problema DELES, não apenas o seu produto.
Use dados reais e específicos. Máximo 250 palavras.
Sempre termine com um call-to-action específico: demonstração de 20 minutos.
Escreva em português brasileiro formal.

{PRODUCT_CONTEXT}
"""

def generate_prospecting_email(prospect_key: str) -> dict:
    """Gera e-mail de prospecção personalizado para um prospect específico."""
    if prospect_key not in PROSPECTS:
        return {"error": f"Prospect '{prospect_key}' não encontrado"}

    p = PROSPECTS[prospect_key]

    prompt = f"""Redija um e-mail de prospecção para:

Empresa: {p['empresa']}
Contato: {p['contato']} — {p['cargo']}
Setor: {p['setor']}

Contexto específico da empresa:
{p['contexto']}

Resultado do OmniUil mais relevante para esse cliente:
{p['resultado_relevante']}

Urgência principal:
{p['urgencia']}

O e-mail deve:
1. Abrir com referência específica a algo que a empresa fez/publicou (não genérico)
2. Apresentar o problema PQC no contexto DELES (não do produto)
3. Mostrar o resultado real do OmniUil em projetos similares ao stack deles
4. Fazer um único pedido claro: 20 minutos de demonstração ao vivo
5. Não mencionar preços
"""

    resp = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": EMAIL_SYSTEM},
            {"role": "user", "content": prompt}
        ],
        temperature=0.7,
        max_tokens=500
    )

    email_body = resp.choices[0].message.content.strip()
    subject = f"OmniUil AI — Conformidade PQC para {p['empresa']} (CNSA 2.0 obrigatório em 2027)"

    # Adiciona como ação pendente para aprovação
    action_id = add_pending(
        agent=MERCURY_NAME,
        action_type="prospecting_email",
        subject=subject,
        to_email=p["email"],
        content=email_body,
        context=json.dumps({
            "empresa": p["empresa"],
            "contato": p["contato"],
            "cargo": p["cargo"],
            "setor": p["setor"],
            "urgencia": p["urgencia"]
        })
    )

    print(f"✅ E-mail de prospecção para {p['empresa']} criado (ID #{action_id})")
    return {"action_id": action_id, "empresa": p["empresa"], "email": p["email"]}

def generate_all_prospects():
    """Gera e-mails de prospecção para todos os prospects cadastrados."""
    print("🚀 Gerando e-mails de prospecção para todos os prospects...")
    results = []
    for key in PROSPECTS:
        result = generate_prospecting_email(key)
        results.append(result)
    print(f"\n✅ {len(results)} e-mails gerados — aguardando sua aprovação no dashboard")
    return results

if __name__ == "__main__":
    generate_all_prospects()
