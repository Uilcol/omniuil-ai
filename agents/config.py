"""
OmniUil AI Agents — Configuração Central
"""
import os

GROQ_API_KEY     = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO      = "Uilcol/omniuil-ai"
GMAIL_CREDS_FILE = os.path.join(os.path.dirname(__file__), "gmail_credentials.json")
GMAIL_TOKEN_FILE = os.path.join(os.path.dirname(__file__), "gmail_token.json")
DB_PATH          = os.path.join(os.path.dirname(__file__), "agents.db")
DASHBOARD_PORT   = 9090

# Modelo Groq
GROQ_MODEL = "qwen/qwen3.8-27b"

# Identidade dos agentes
MERCURY_NAME = "Mercury"
VULCAN_NAME  = "Vulcan"

# E-mail do fundador (para aprovação)
FOUNDER_EMAIL = "omniuil.ai@gmail.com"  # preencha com seu Gmail

# Contexto do produto (injetado nos prompts)
PRODUCT_CONTEXT = """
OmniUil AI é um scanner de segurança criptográfica pós-quântica.
- Engine Rust com 33 regras PQC alinhadas ao NIST FIPS 203/204/205
- Taint analysis: rastreia dados externos até operações criptográficas
- 5 linguagens: Python, Java, Go, JavaScript/TypeScript, Rust, C#
- 100%% local — nenhum código sai da máquina do cliente (LGPD)
- 5 agentes IA (Ollama local): Scanner, Analysis, Remediation, Monitoring, Incident
- Planos: Free (CLI Apache 2.0), Starter, Pro, Enterprise
- Repositório: https://github.com/Uilcol/omniuil-ai
- Formulário de contato: https://docs.google.com/forms/d/e/1FAIpQLSfNMleQF2Ik-jHTT5HgPdsdkirXc4U_eJV3ON2hzI8ZR1TmQg/viewform
- Case studies: 51 findings no WebGoat OWASP, 443 no Keycloak, 437 no Spring Security
- Diferencial vs concorrentes: único com PQC em 5 linguagens + IA local + 100%% on-premise
"""
