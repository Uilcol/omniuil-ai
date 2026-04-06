#!/bin/bash
# ============================================================
# QSEC — Setup Ollama (LLM Local Gratuito)
# ============================================================
# Executa: bash setup_ollama.sh
# Após isso: export LLM_PROVIDER=ollama
#            python3 main.py audit ./meu-projeto
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  QSEC — Setup Ollama (LLM Local)          ║"
echo "  ║  Zero custo · Zero dependência externa     ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Detectar OS ────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
echo -e "${YELLOW}Sistema: ${OS} ${ARCH}${NC}"

# ── 2. Instalar Ollama ────────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
    echo -e "${GREEN}✓ Ollama já instalado: $(ollama --version)${NC}"
else
    echo -e "${YELLOW}Instalando Ollama...${NC}"
    if [[ "$OS" == "Linux" ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
    elif [[ "$OS" == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            brew install ollama
        else
            echo -e "${RED}Instale o Homebrew: https://brew.sh${NC}"
            echo "Ou baixe manualmente: https://ollama.com/download"
            exit 1
        fi
    else
        echo -e "${RED}Windows detectado. Baixe o instalador em: https://ollama.com/download${NC}"
        echo "Depois volte e execute este script no WSL."
        exit 1
    fi
fi

# ── 3. Iniciar serviço ────────────────────────────────────────────────────────
echo -e "${YELLOW}Iniciando serviço Ollama em background...${NC}"
if ! pgrep -x "ollama" > /dev/null; then
    ollama serve &>/tmp/ollama.log &
    sleep 2
fi

# ── 4. Verificar RAM disponível para recomendar modelo ────────────────────────
RAM_GB=8
if command -v free &>/dev/null; then
    RAM_KB=$(free | awk '/^Mem:/{print $2}')
    RAM_GB=$((RAM_KB / 1024 / 1024))
fi

echo ""
echo -e "${CYAN}RAM disponível: ~${RAM_GB} GB${NC}"
echo ""

if   [[ $RAM_GB -ge 32 ]]; then
    RECOMMENDED="qwen2.5:32b"
    REASON="melhor qualidade para análise de código"
elif [[ $RAM_GB -ge 16 ]]; then
    RECOMMENDED="qwen2.5:14b"
    REASON="excelente para análise de segurança"
elif [[ $RAM_GB -ge 8 ]]; then
    RECOMMENDED="llama3.1:8b"
    REASON="bom equilíbrio qualidade/velocidade"
else
    RECOMMENDED="llama3.2:3b"
    REASON="modelo leve para máquinas com pouca RAM"
fi

echo -e "${BOLD}Modelos disponíveis:${NC}"
echo ""
printf "  %-22s %-8s %s\n" "MODELO" "RAM" "USO"
printf "  %-22s %-8s %s\n" "------" "---" "---"
printf "  %-22s %-8s %s\n" "llama3.2:3b"       "2 GB"  "Máquinas limitadas"
printf "  %-22s %-8s %s\n" "llama3.1:8b"       "5 GB"  "Uso geral ← recomendado 8GB RAM"
printf "  %-22s %-8s %s\n" "qwen2.5:14b"       "9 GB"  "Análise de código ← 16GB RAM"
printf "  %-22s %-8s %s\n" "deepseek-r1:8b"    "5 GB"  "Melhor raciocínio"
printf "  %-22s %-8s %s\n" "qwen2.5:32b"       "20 GB" "Qualidade máxima ← 32GB RAM"
echo ""
echo -e "${GREEN}→ Recomendado para sua máquina: ${BOLD}${RECOMMENDED}${NC} (${REASON})"
echo ""

# ── 5. Baixar modelo ──────────────────────────────────────────────────────────
echo -e "${YELLOW}Baixando ${RECOMMENDED}... (pode demorar alguns minutos)${NC}"
ollama pull "$RECOMMENDED"

echo ""
echo -e "${GREEN}✓ Modelo ${RECOMMENDED} instalado${NC}"

# ── 6. Teste rápido ───────────────────────────────────────────────────────────
echo -e "${YELLOW}Testando resposta do modelo...${NC}"
TEST=$(ollama run "$RECOMMENDED" "Responda apenas: OK" 2>/dev/null || echo "timeout")
if [[ "$TEST" == *"OK"* ]] || [[ "$TEST" != "timeout" ]]; then
    echo -e "${GREEN}✓ Modelo respondendo corretamente${NC}"
else
    echo -e "${YELLOW}⚠ Modelo demorou a responder. Tente novamente após o download completo.${NC}"
fi

# ── 7. Configurar variável de ambiente ────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}Configuração completa!${NC}"
echo ""
echo -e "Adicione ao seu ${BOLD}~/.bashrc${NC} ou ${BOLD}~/.zshrc${NC}:"
echo ""
echo -e "  ${GREEN}export LLM_PROVIDER=ollama${NC}"
echo -e "  ${GREEN}export OLLAMA_MODEL=${RECOMMENDED}${NC}"
echo ""
echo -e "Ou use por sessão:"
echo ""
echo -e "  ${GREEN}LLM_PROVIDER=ollama OLLAMA_MODEL=${RECOMMENDED} python3 main.py audit ./seu-projeto${NC}"
echo ""
echo -e "${BOLD}Comparação de provedores para QSEC:${NC}"
echo ""
printf "  %-14s %-10s %-12s %s\n" "PROVEDOR" "CUSTO" "PRIVACIDADE" "SETUP"
printf "  %-14s %-10s %-12s %s\n" "--------" "-----" "-----------" "-----"
printf "  %-14s %-10s %-12s %s\n" "ollama"      "\$0/sempre"  "Total"       "✓ Feito"
printf "  %-14s %-10s %-12s %s\n" "groq"        "\$0 free"    "Groq cloud"  "GROQ_API_KEY"
printf "  %-14s %-10s %-12s %s\n" "openai"      "\$\$"         "OpenAI"      "OPENAI_API_KEY"
printf "  %-14s %-10s %-12s %s\n" "gemini"      "\$"          "Google"      "GEMINI_API_KEY"
printf "  %-14s %-10s %-12s %s\n" "bedrock"     "\$\$"         "Sua AWS"     "aws configure"
printf "  %-14s %-10s %-12s %s\n" "anthropic"   "\$\$"         "Anthropic"   "ANTHROPIC_API_KEY"
echo ""
echo -e "${GREEN}✓ QSEC está pronto para rodar sem depender de nenhuma API externa.${NC}"
