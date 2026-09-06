#!/bin/bash
# OmniUil AI Agents — Inicialização
echo "⚡ Iniciando OmniUil AI Agents..."
cd ~/QSEC/agents

# Verifica dependências
python3 -c "import groq, flask, google.auth" 2>/dev/null || {
    echo "Instalando dependências..."
    pip install groq flask google-auth-oauthlib google-auth-httplib2 google-api-python-client requests
}

# Inicializa banco
python3 -c "from db import init_db; init_db()"

# Inicia dashboard
echo "Dashboard disponível em http://localhost:9090"
python3 dashboard.py
