# OmniUil AI — Checklist de Pré-Lançamento

**Regra:** nada é publicado (HN, LinkedIn, repo público) até os itens marcados
🔴 BLOQUEADOR estarem 100% concluídos. Itens 🟡 podem esperar a v3.5.

---

## FASE 1 — Infraestrutura de Cobrança (VOCÊ precisa fazer — exige CPF/CNPJ)

### 🔴 1.1 — Abrir MEI (Microempreendedor Individual)
Sem isso você não pode emitir nota fiscal nem abrir conta PJ.

- Acesse: https://www.gov.br/empresas-e-negocios/pt-br/empreendedor
- CNAE sugerido: **6209-1/00** (Suporte técnico, manutenção e outros
  serviços em tecnologia da informação) ou **6201-5/01** (Desenvolvimento
  de programas de computador sob encomenda)
- Custo: gratuito, leva ~10 minutos, CNPJ sai na hora
- Limite de faturamento MEI: R$ 81.000/ano — se ultrapassar rápido,
  planeje migrar para ME (Microempresa) depois

### 🔴 1.2 — Conta bancária PJ
- Recomendo: **Banco Inter** ou **Nubank PJ** — abertura 100% digital,
  gratuita, PIX incluso, emite boleto
- Precisa do CNPJ do MEI (passo 1.1) em mãos

### 🔴 1.3 — Conta Stripe (para cartão internacional — Matera, ITI e
   clientes futuros vão preferir isso a PIX)
- Acesse: https://dashboard.stripe.com/register
- Precisa: CNPJ, conta bancária PJ, dados pessoais
- Ativa "Stripe Payment Links" — gera um link de pagamento sem precisar
  programar nada (ex: "Licença Comercial OmniUil — R$ 9.900/mês")

### 🟡 1.4 — Emissão de Nota Fiscal
- MEI usa o sistema do próprio município (ex: NFS-e) — geralmente grátis
- Alternativa mais simples no início: **Emissor gratuito da prefeitura**
  do seu município (busque "emitir NFS-e MEI [sua cidade]")

**Não publique nada até 1.1, 1.2 e 1.3 estarem prontos.** Sem isso, se a
Matera quiser pagar amanhã, você não tem como receber profissionalmente.

---

## FASE 2 — Canal de Captura de Leads (VOCÊ precisa fazer — 15 min)

### 🔴 2.1 — Criar o Google Forms
Siga exatamente a estrutura em `formulario_comercial_e_readme.md`
(já entregue anteriormente). Resumo rápido:

1. https://forms.google.com → "+ Em branco"
2. Título: "OmniUil AI — Licença Comercial e Demonstração"
3. Copiar os 10 campos do documento anterior
4. Conectar a uma planilha (Respostas → ícone do Sheets)
5. Ativar notificação por e-mail (⋮ → "Receber notificações")
6. Copiar o link de envio (botão "Enviar" → ícone 🔗)

### 🔴 2.2 — Adicionar o link do Stripe Payment Link e do Forms no README
Farei essa parte via comando — só preciso que você me mande os dois links
depois de criados.

---

## FASE 3 — Proteção Técnica Mínima (EU faço — código abaixo)

### 🔴 3.1 — Sistema de licença por chave (90 dias de avaliação)
Código completo abaixo. Adiciona ao `qsec-enterprise/api/server.py`.

### 🔴 3.2 — Telemetria opcional e transparente
Código completo abaixo. Opt-out claro, documentado no README.

### 🟡 3.3 — Dashboard de licenças (ver quem está usando)
Fica para v3.5 — não é bloqueador para publicar.

---

## FASE 4 — Publicação (só depois de Fase 1, 2 e 3 concluídas)

1. Tornar repositório público
2. Publicar no LinkedIn
3. Publicar Show HN
4. Responder ativamente por 48h (checar formulário e comentários a cada
   poucas horas)

---

## Ordem de execução recomendada para HOJE

```
Manhã   → Fase 1.1 (MEI) — 10 min, sai na hora
        → Fase 1.2 (conta PJ) — 15 min, aprovação pode levar 1-2 dias
Tarde   → Fase 1.3 (Stripe) — 20 min, aprovação pode levar até 24h
        → Fase 2.1 (Google Forms) — 15 min
Noite   → Aplicar código da Fase 3 (eu já deixo pronto abaixo)
        → Testar tudo localmente
Amanhã  → Se Stripe já aprovou: publicar
        → Se não: aguardar aprovação antes de publicar
```

**Realidade:** Stripe e conta PJ podem levar 1-2 dias úteis para aprovar.
Isso significa que a publicação hoje é possível, mas o **link de
pagamento funcional** pode só estar pronto amanhã ou depois de amanhã.
Isso é normal e aceitável — o formulário de contato já funciona hoje
como ponte, você negocia manualmente enquanto o Stripe não aprova.
