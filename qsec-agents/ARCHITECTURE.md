
QSEC Multi-Agent System — Arquitetura

┌─────────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR (Python)                           │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   AgentBus (message router)                  │   │
│  └───┬──────────┬──────────┬──────────┬──────────┬─────────────┘   │
│      │          │          │          │          │                  │
│  ┌───▼──┐  ┌───▼──┐  ┌───▼──┐  ┌───▼──┐  ┌───▼──┐               │
│  │SCAN  │  │ANAL  │  │REMED │  │MONIT │  │INCID │               │
│  │Agent │  │Agent │  │Agent │  │Agent │  │Agent │               │
│  └───┬──┘  └───┬──┘  └───┬──┘  └───┬──┘  └───┬──┘               │
│      │          │          │          │          │                  │
│  ┌───▼──────────▼──────────▼──────────▼──────────▼─────────────┐   │
│  │              SharedMemory (estado compartilhado)             │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ subprocess / JSON
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    QSEC ENGINE (Rust v3)                            │
│                                                                     │
│  qsec scan │ qsec sign │ qsec verify │ qsec sbom │ qsec pipeline   │
│  qsec token │ qsec keys │ qsec apikey │ qsec info                  │
└─────────────────────────────────────────────────────────────────────┘

Fluxo:
  1. Orchestrator recebe tarefa (ex: "analise segurança do projeto X")
  2. Chama ScannerAgent → executa qsec scan → retorna findings JSON
  3. Chama AnalysisAgent (Claude API) → interpreta findings com contexto
  4. Se CRITICAL → RemediationAgent gera patches de código
  5. MonitoringAgent fica em loop observando mudanças
  6. IncidentAgent responde a comprometimentos de chave em tempo real
