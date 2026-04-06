#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  QSEC Enterprise — Instalador Automático
#  Linux · macOS · WSL2
#
#  Uso:
#    curl -fsSL https://raw.githubusercontent.com/SEU_USUARIO/qsec/main/install.sh | bash
#
#  Ou baixe e execute:
#    bash install.sh
#
#  O QUE ESTE SCRIPT FAZ:
#    1. Verifica/instala Docker
#    2. Baixa o QSEC (docker-compose.yml)
#    3. Gera senha segura automaticamente
#    4. Inicia toda a stack (QSEC + Ollama)
#    5. Baixa o modelo de IA (~2 GB, uma única vez)
#    6. Abre o navegador no dashboard
#
#  NADA É ENVIADO PARA FORA DA SUA MÁQUINA.
#  Código analisado, modelo LLM e dados ficam 100% locais.
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Cores ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'

QSEC_VERSION="3.2.1"
QSEC_REPO="https://github.com/SEU_USUARIO/qsec"  # substitua com seu repo
QSEC_RAW="https://raw.githubusercontent.com/SEU_USUARIO/qsec/main"
INSTALL_DIR="${QSEC_INSTALL_DIR:-$HOME/.qsec}"
COMPOSE_URL="$QSEC_RAW/qsec-enterprise/docker/docker-compose.yml"
PORT="${QSEC_PORT:-8080}"

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
  echo -e "${C}${B}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║   QSEC Enterprise v${QSEC_VERSION}                        ║"
  echo "  ║   Post-Quantum Cryptographic Firewall            ║"
  echo "  ║   Instalação automática — 100% local e privado   ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${N}"
}

# ── Utilitários ───────────────────────────────────────────────────────────────
step()  { echo -e "${C}${B}[$(date +%H:%M:%S)] $*${N}"; }
ok()    { echo -e "  ${G}✓${N} $*"; }
warn()  { echo -e "  ${Y}!${N} $*"; }
fail()  { echo -e "  ${R}✗ ERRO: $*${N}"; exit 1; }
nl()    { echo; }

# ── Detecção de OS ────────────────────────────────────────────────────────────
detect_os() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  case "$OS" in
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then
        OS_TYPE="wsl"
      else
        OS_TYPE="linux"
      fi
      ;;
    Darwin)  OS_TYPE="macos" ;;
    *)       fail "Sistema não suportado: $OS. Use WSL2 no Windows." ;;
  esac
  ok "Sistema: $OS_TYPE ($ARCH)"
}

# ── Verificar/Instalar Docker ─────────────────────────────────────────────────
check_docker() {
  step "Verificando Docker..."

  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    DOCKER_VER=$(docker --version | grep -oP '\d+\.\d+' | head -1)
    ok "Docker $DOCKER_VER encontrado e rodando"
    return 0
  fi

  if command -v docker &>/dev/null; then
    fail "Docker instalado mas não está rodando. Inicie o Docker Desktop e tente novamente."
  fi

  warn "Docker não encontrado. Instalando..."
  nl

  case "$OS_TYPE" in
    linux)
      curl -fsSL https://get.docker.com | sh
      sudo usermod -aG docker "$USER"
      sudo systemctl enable --now docker
      ok "Docker instalado. IMPORTANTE: faça logout e login novamente se necessário."
      ;;
    wsl)
      echo -e "${Y}  → No WSL2, instale o Docker Desktop no Windows:${N}"
      echo "    https://www.docker.com/products/docker-desktop"
      echo "    Certifique-se de ativar 'Use WSL2 based engine' nas configurações."
      fail "Instale o Docker Desktop e execute novamente."
      ;;
    macos)
      if command -v brew &>/dev/null; then
        brew install --cask docker
        open /Applications/Docker.app
        warn "Docker Desktop instalado. Aguardando inicialização..."
        sleep 8
      else
        echo -e "${Y}  → Baixe o Docker Desktop para Mac:${N}"
        echo "    https://www.docker.com/products/docker-desktop"
        fail "Instale o Docker Desktop e execute novamente."
      fi
      ;;
  esac
}

# ── Verificar docker compose ──────────────────────────────────────────────────
check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    ok "Docker Compose plugin disponível"
  elif command -v docker-compose &>/dev/null; then
    ok "docker-compose disponível (legado)"
    # alias para compatibilidade
    docker() { if [ "$1" = "compose" ]; then shift; command docker-compose "$@"; else command docker "$@"; fi; }
    export -f docker
  else
    fail "Docker Compose não encontrado. Atualize o Docker Desktop."
  fi
}

# ── Escolher modelo LLM baseado na RAM disponível ─────────────────────────────
choose_model() {
  step "Detectando RAM disponível para escolher modelo de IA..."

  RAM_GB=8
  if [[ "$OS_TYPE" == "linux" || "$OS_TYPE" == "wsl" ]]; then
    RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 8388608)
    RAM_GB=$(( RAM_KB / 1024 / 1024 ))
  elif [[ "$OS_TYPE" == "macos" ]]; then
    RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 8589934592)
    RAM_GB=$(( RAM_BYTES / 1024 / 1024 / 1024 ))
  fi

  nl
  echo -e "  ${B}RAM detectada: ~${RAM_GB} GB${N}"
  nl
  echo -e "  ${B}Modelos disponíveis:${N}"
  printf "    %-24s %-8s %-12s %s\n" "MODELO" "TAMANHO" "RAM MÍNIMA" "QUALIDADE"
  printf "    %-24s %-8s %-12s %s\n" "------" "-------" "----------" "---------"
  printf "    %-24s %-8s %-12s %s\n" "llama3.2:3b (padrão)" "2 GB" "4 GB" "Boa"
  printf "    %-24s %-8s %-12s %s\n" "llama3.1:8b"           "5 GB" "8 GB" "Muito Boa"
  printf "    %-24s %-8s %-12s %s\n" "qwen2.5:14b"           "9 GB" "16 GB" "Excelente"
  printf "    %-24s %-8s %-12s %s\n" "qwen2.5:32b"           "20 GB" "32 GB" "Máxima"
  nl

  if   [[ $RAM_GB -ge 32 ]]; then MODEL_DEFAULT="qwen2.5:32b"
  elif [[ $RAM_GB -ge 16 ]]; then MODEL_DEFAULT="qwen2.5:14b"
  elif [[ $RAM_GB -ge 8  ]]; then MODEL_DEFAULT="llama3.1:8b"
  else                             MODEL_DEFAULT="llama3.2:3b"
  fi

  # Não interativo (pipe) — usa recomendado automaticamente
  if [ ! -t 0 ]; then
    OLLAMA_MODEL="$MODEL_DEFAULT"
    ok "Modelo selecionado automaticamente: $OLLAMA_MODEL"
    return
  fi

  echo -ne "  ${C}Modelo recomendado para sua máquina: ${B}${MODEL_DEFAULT}${N}${C}. Confirma? [Enter=sim / digite outro]: ${N}"
  read -r USER_MODEL
  OLLAMA_MODEL="${USER_MODEL:-$MODEL_DEFAULT}"
  ok "Modelo selecionado: $OLLAMA_MODEL"
}

# ── Gerar configuração ────────────────────────────────────────────────────────
generate_config() {
  step "Criando diretório de instalação: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  # Baixar docker-compose.yml
  # Tenta usar arquivo local primeiro (entrega offline), depois baixa do GitHub
  # Detecta o diretório do script de forma robusta (compatível com WSL)
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
  COMPOSE_LOCAL="${SCRIPT_DIR}/docker/docker-compose.yml"
  COMPOSE_LOCAL2="${SCRIPT_DIR}/docker-compose.yml"
  if [ -f "$COMPOSE_LOCAL" ]; then
    cp "$COMPOSE_LOCAL" docker-compose.yml
    ok "docker-compose.yml carregado (local)"
  elif [ -f "$COMPOSE_LOCAL2" ]; then
    cp "$COMPOSE_LOCAL2" docker-compose.yml
    ok "docker-compose.yml carregado (local)"
  elif command -v curl &>/dev/null; then
    curl -fsSL "$COMPOSE_URL" -o docker-compose.yml 2>/dev/null || \
      fail "Não foi possível baixar docker-compose.yml. Execute a partir do pacote QSEC."
    ok "docker-compose.yml baixado do GitHub"
  else
    fail "Execute este script a partir do pacote QSEC descompactado."
  fi

  # Gerar senha segura (32 bytes hex = 64 chars)
  if command -v openssl &>/dev/null; then
    SECRET=$(openssl rand -hex 32)
  else
    SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 64)
  fi

  # Criar .env se não existir
  if [ -f .env ]; then
    warn ".env já existe — mantendo configuração atual"
    # Atualiza apenas o modelo se mudou
    sed -i.bak "s/^OLLAMA_MODEL=.*/OLLAMA_MODEL=${OLLAMA_MODEL}/" .env 2>/dev/null || true
  else
    cat > .env << ENVEOF
# ═══════════════════════════════════════════════════
# QSEC Enterprise — Configuração
# Gerado automaticamente em $(date)
# ═══════════════════════════════════════════════════

# Senha de acesso ao dashboard (não compartilhe)
QSEC_API_SECRET=${SECRET}

# Modelo de IA local — sem custo, sem API externa
LLM_PROVIDER=ollama
OLLAMA_MODEL=${OLLAMA_MODEL}
OLLAMA_TIMEOUT=180

# Porta do dashboard
PORT=${PORT}

# Pasta do projeto para escanear (edite conforme necessário)
# Exemplo Linux/Mac: SCAN_TARGET=/home/usuario/meu-projeto
# Exemplo WSL:       SCAN_TARGET=/mnt/c/Users/usuario/meu-projeto
SCAN_TARGET=${HOME}/projects

# ── Provedores alternativos (opcionais — deixe em branco para usar Ollama) ──
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GROQ_API_KEY=gsk_...
ENVEOF
    ok ".env gerado com senha segura"
  fi

  # Criar atalho para o diretório de escaneamento
  mkdir -p "${HOME}/projects" 2>/dev/null || true
}

# ── Iniciar a stack ───────────────────────────────────────────────────────────
start_stack() {
  step "Baixando imagens Docker (primeira vez pode demorar alguns minutos)..."
  nl
  docker compose pull --quiet 2>/dev/null || true

  step "Iniciando QSEC + Ollama..."
  docker compose up -d --build

  nl
  step "Aguardando QSEC ficar pronto..."

  # Espera até 120s pelo health check
  for i in $(seq 1 24); do
    if curl -sf "http://localhost:${PORT}/health" &>/dev/null; then
      ok "QSEC API online!"
      break
    fi
    if [ $i -eq 24 ]; then
      warn "Timeout aguardando QSEC. Verifique com: docker compose logs qsec-api"
    fi
    echo -n "."
    sleep 5
  done
  echo

  step "Aguardando modelo de IA ser baixado (${OLLAMA_MODEL})..."
  warn "Isso pode demorar alguns minutos na primeira vez (~2-20 GB)."
  warn "Próximas inicializações serão instantâneas (modelo em cache)."
  nl

  # Mostra logs do ollama-init em tempo real
  docker compose logs -f ollama-init 2>/dev/null &
  LOGS_PID=$!
  docker compose wait ollama-init 2>/dev/null || true
  kill $LOGS_PID 2>/dev/null || true
  ok "Modelo de IA pronto!"
}

# ── Mostrar informações finais ────────────────────────────────────────────────
show_summary() {
  # Ler a senha gerada
  API_SECRET=$(grep QSEC_API_SECRET "$INSTALL_DIR/.env" | cut -d= -f2)

  nl
  echo -e "${G}${B}╔════════════════════════════════════════════════════════╗${N}"
  echo -e "${G}${B}║           QSEC instalado com sucesso! ✅               ║${N}"
  echo -e "${G}${B}╚════════════════════════════════════════════════════════╝${N}"
  nl
  echo -e "  ${B}Dashboard:${N}   ${C}http://localhost:${PORT}${N}"
  echo -e "  ${B}API Secret:${N}  ${Y}${API_SECRET}${N}"
  nl
  echo -e "  ${B}Modelo IA:${N}   ${OLLAMA_MODEL} (local, gratuito, privado)"
  echo -e "  ${B}Instalado em:${N} ${INSTALL_DIR}"
  nl
  echo -e "  ${B}Comandos úteis:${N}"
  echo -e "    ${C}cd ${INSTALL_DIR} && docker compose logs -f${N}     # ver logs"
  echo -e "    ${C}cd ${INSTALL_DIR} && docker compose down${N}         # parar"
  echo -e "    ${C}cd ${INSTALL_DIR} && docker compose up -d${N}        # reiniciar"
  echo -e "    ${C}cd ${INSTALL_DIR} && docker compose pull && docker compose up -d${N}  # atualizar"
  nl
  echo -e "  ${Y}Salve a senha acima — ela é necessária para acessar o dashboard.${N}"
  echo -e "  ${Y}Ela também está salva em: ${INSTALL_DIR}/.env${N}"
  nl

  # Criar arquivo de atalho com as informações
  cat > "$INSTALL_DIR/ACESSO.txt" << INFOEOF
QSEC Enterprise v${QSEC_VERSION}
════════════════════════════

Dashboard: http://localhost:${PORT}
Senha:     ${API_SECRET}
Modelo IA: ${OLLAMA_MODEL} (local, sem custo)

Comandos:
  Parar:      cd ${INSTALL_DIR} && docker compose down
  Iniciar:    cd ${INSTALL_DIR} && docker compose up -d
  Logs:       cd ${INSTALL_DIR} && docker compose logs -f
  Atualizar:  cd ${INSTALL_DIR} && docker compose pull && docker compose up -d

Escanear um projeto:
  Edite SCAN_TARGET no arquivo .env apontando para seu código.
  Reinicie com: docker compose up -d
INFOEOF

  ok "Informações de acesso salvas em: ${INSTALL_DIR}/ACESSO.txt"
}

# ── Abrir navegador ───────────────────────────────────────────────────────────
open_browser() {
  URL="http://localhost:${PORT}"
  step "Abrindo dashboard no navegador: $URL"
  sleep 2

  case "$OS_TYPE" in
    macos) open "$URL" ;;
    wsl)   cmd.exe /c start "$URL" 2>/dev/null || true ;;
    linux) xdg-open "$URL" 2>/dev/null || \
           sensible-browser "$URL" 2>/dev/null || \
           warn "Abra manualmente: $URL" ;;
  esac
}

# ── Fluxo principal ───────────────────────────────────────────────────────────
main() {
  banner
  detect_os
  check_docker
  check_compose
  choose_model
  generate_config
  start_stack
  show_summary
  open_browser

  nl
  echo -e "${G}${B}QSEC está rodando. Acesse: http://localhost:${PORT}${N}"
  nl
}

main "$@"
