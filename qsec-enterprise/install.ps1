# ═══════════════════════════════════════════════════════════════════════════
#  QSEC Enterprise — Instalador para Windows
#
#  Execute no PowerShell como Administrador:
#  irm https://raw.githubusercontent.com/SEU_USUARIO/qsec/main/install.ps1 | iex
#
#  OU baixe e execute:
#  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#  .\install.ps1
# ═══════════════════════════════════════════════════════════════════════════

param(
    [string]$InstallDir = "$env:USERPROFILE\.qsec",
    [int]$Port = 8080,
    [string]$Model = "auto"
)

$ErrorActionPreference = "Stop"
$QsecVersion  = "3.2.1"
$ComposeUrl   = "https://raw.githubusercontent.com/SEU_USUARIO/qsec/main/qsec-enterprise/docker/docker-compose.yml"

# ── Cores ─────────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  [X]  ERRO: $msg" -ForegroundColor Red; exit 1 }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   QSEC Enterprise v$QsecVersion                        ║" -ForegroundColor Cyan
Write-Host "  ║   Post-Quantum Cryptographic Firewall            ║" -ForegroundColor Cyan
Write-Host "  ║   Instalação automática — Windows                ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Verificar Docker ──────────────────────────────────────────────────────────
Write-Step "Verificando Docker Desktop..."

try {
    $dockerInfo = docker info 2>&1
    $dockerVer  = (docker --version) -replace "Docker version ", "" -replace ",.*", ""
    Write-Ok "Docker $dockerVer encontrado e rodando"
} catch {
    Write-Host ""
    Write-Warn "Docker Desktop não encontrado ou não está rodando."
    Write-Host ""
    Write-Host "  1. Baixe o Docker Desktop em:" -ForegroundColor Yellow
    Write-Host "     https://www.docker.com/products/docker-desktop" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Instale e inicie o Docker Desktop"
    Write-Host "  3. Execute este script novamente"
    Write-Host ""

    $open = Read-Host "Abrir página de download agora? [S/n]"
    if ($open -ne "n" -and $open -ne "N") {
        Start-Process "https://www.docker.com/products/docker-desktop"
    }
    exit 1
}

# ── Detectar RAM e recomendar modelo ──────────────────────────────────────────
Write-Step "Detectando RAM disponível..."

$TotalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
Write-Ok "RAM: ~${TotalRAM} GB"

if     ($TotalRAM -ge 32) { $RecommendedModel = "qwen2.5:32b" }
elseif ($TotalRAM -ge 16) { $RecommendedModel = "qwen2.5:14b" }
elseif ($TotalRAM -ge 8)  { $RecommendedModel = "llama3.1:8b" }
else                       { $RecommendedModel = "llama3.2:3b" }

Write-Host ""
Write-Host "  Modelos disponíveis:" -ForegroundColor White
Write-Host "    llama3.2:3b   2 GB   4 GB RAM   Boa" -ForegroundColor Gray
Write-Host "    llama3.1:8b   5 GB   8 GB RAM   Muito Boa" -ForegroundColor Gray
Write-Host "    qwen2.5:14b   9 GB   16 GB RAM  Excelente" -ForegroundColor Gray
Write-Host "    qwen2.5:32b  20 GB   32 GB RAM  Máxima" -ForegroundColor Gray
Write-Host ""

if ($Model -eq "auto") {
    $UserModel = Read-Host "  Modelo recomendado: $RecommendedModel. Confirma? [Enter=sim / digite outro]"
    $OllamaModel = if ($UserModel -eq "") { $RecommendedModel } else { $UserModel }
} else {
    $OllamaModel = $Model
}
Write-Ok "Modelo selecionado: $OllamaModel"

# ── Criar diretório de instalação ─────────────────────────────────────────────
Write-Step "Criando diretório de instalação: $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# ── Baixar docker-compose.yml ─────────────────────────────────────────────────
Write-Step "Baixando configuração QSEC..."
$LocalCompose = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "docker\docker-compose.yml"
if (Test-Path $LocalCompose) {
    Copy-Item $LocalCompose "$InstallDir\docker-compose.yml" -Force
    Write-Ok "docker-compose.yml carregado (local)"
} else {
    try {
        Invoke-WebRequest -Uri $ComposeUrl -OutFile "$InstallDir\docker-compose.yml" -UseBasicParsing
        Write-Ok "docker-compose.yml baixado do GitHub"
    } catch {
        Write-Fail "Execute a partir do pacote QSEC descompactado. Erro: $_"
    }
}

# ── Gerar senha segura ────────────────────────────────────────────────────────
$SecretBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($SecretBytes)
$Secret = [System.BitConverter]::ToString($SecretBytes).Replace("-","").ToLower()

# Pasta de projetos do usuário para escanear
$ProjectsDir = "$env:USERPROFILE\projects"
New-Item -ItemType Directory -Path $ProjectsDir -Force | Out-Null

# ── Criar .env ────────────────────────────────────────────────────────────────
$EnvFile = "$InstallDir\.env"
if (Test-Path $EnvFile) {
    Write-Warn ".env já existe — mantendo configuração atual"
} else {
    $EnvContent = @"
# QSEC Enterprise — Configuração
# Gerado automaticamente em $(Get-Date)

QSEC_API_SECRET=$Secret

LLM_PROVIDER=ollama
OLLAMA_MODEL=$OllamaModel
OLLAMA_TIMEOUT=180

PORT=$Port

# Pasta do projeto para escanear (use barras normais /)
# Exemplo: SCAN_TARGET=C:/Users/$env:USERNAME/meu-projeto
SCAN_TARGET=$($ProjectsDir -replace '\\','/')

# Providers alternativos (opcionais)
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GROQ_API_KEY=gsk_...
"@
    Set-Content -Path $EnvFile -Value $EnvContent -Encoding UTF8
    Write-Ok ".env gerado com senha segura"
}

# ── Iniciar a stack ───────────────────────────────────────────────────────────
Write-Step "Iniciando QSEC + Ollama (primeira vez pode demorar)..."
Set-Location $InstallDir

& docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Write-Fail "Falha ao iniciar Docker Compose" }

# ── Aguardar QSEC ─────────────────────────────────────────────────────────────
Write-Step "Aguardando QSEC ficar pronto..."
$Ready = $false
for ($i = 0; $i -lt 24; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 3
        if ($response.StatusCode -eq 200) { $Ready = $true; break }
    } catch {}
    Write-Host "." -NoNewline
    Start-Sleep 5
}
Write-Host ""
if ($Ready) { Write-Ok "QSEC API online!" }
else { Write-Warn "Timeout — verifique com: docker compose logs qsec-api" }

# ── Aguardar modelo ───────────────────────────────────────────────────────────
Write-Step "Aguardando download do modelo $OllamaModel..."
Write-Warn "Primeira vez: pode demorar alguns minutos (~2-20 GB)."
Write-Warn "Próximas inicializações serão instantâneas (cache local)."
& docker compose wait ollama-init 2>$null

Write-Ok "Modelo de IA pronto!"

# ── Salvar informações de acesso ──────────────────────────────────────────────
$AccessInfo = @"
QSEC Enterprise v$QsecVersion
════════════════════════════

Dashboard: http://localhost:$Port
Senha:     $Secret
Modelo IA: $OllamaModel (local, sem custo)

Comandos PowerShell (execute em $InstallDir):
  Parar:      docker compose down
  Iniciar:    docker compose up -d
  Logs:       docker compose logs -f
  Atualizar:  docker compose pull; docker compose up -d
"@
Set-Content -Path "$InstallDir\ACESSO.txt" -Value $AccessInfo -Encoding UTF8

# ── Resumo final ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║           QSEC instalado com sucesso!                  ║" -ForegroundColor Green
Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:  " -NoNewline; Write-Host "http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  Senha:      " -NoNewline; Write-Host $Secret -ForegroundColor Yellow
Write-Host "  Modelo IA:  " -NoNewline; Write-Host "$OllamaModel (local, gratuito)" -ForegroundColor Green
Write-Host ""
Write-Host "  Acesso salvo em: $InstallDir\ACESSO.txt" -ForegroundColor Gray
Write-Host ""

# ── Abrir navegador ───────────────────────────────────────────────────────────
Start-Sleep 2
Start-Process "http://localhost:$Port"
Write-Host "  Dashboard aberto no navegador!" -ForegroundColor Green
Write-Host ""
