# BENCHMARK — QSEC Scanner em repos reais

> **Aviso importante:** este benchmark existe para documentar o estado atual
> do scanner, incluindo suas limitacoes. Nenhum dos repos escaneados tem
> vulnerabilidade real — ambos implementam criptografia corretamente. Os
> "findings" reportados sao ocorrencias de algoritmos classicos (RSA, ECDSA)
> que sao **obrigatorias** nessas bibliotecas, nao bugs.

**Data:** 2026-09-28
**Versao do scanner:** v3.3.0 (backend: reference)
**Comando:** `qsec scan <repo> --format text`

---

## Resumo

| Repo | Linguagem | Findings | CRITICAL | MEDIUM | Top regra |
|------|-----------|----------|----------|--------|-----------|
| `auth0/node-jsonwebtoken` | JavaScript | 8 | 8 | 0 | QSC-001 (RSA) |
| `jpadilla/pyjwt` | Python | 79 | 77 | 2 | QSC-002 (ECDSA) |

**Total:** 87 findings em 2 repos publicos.

---

## Repo 1 — node-jsonwebtoken (JavaScript)

**Tamanho:** ~10 MB, ~40 arquivos JS.
**Funcao:** Biblioteca canonica de JWT no ecossistema Node.js.

### Distribuicao

| Regra | Severidade | Ocorrencias | Significado |
|-------|-----------|-------------|-------------|
| QSC-001 | CRITICAL | 6 | RSA em `validateAsymmetricKey.js` e `verify.js` |
| QSC-002 | CRITICAL | 2 | ECDSA em `validateAsymmetricKey.js` |

### Onde disparou

- `lib/validateAsymmetricKey.js` — tabela de algoritmos suportados (`rsa`, `rsa-pss`, `ec`)
- `verify.js:135` — deteccao de tipo de chave

### Interpretacao

**Nenhum finding e bug.** O `node-jsonwebtoken` **precisa** suportar RS256/PS256/ES256
para ser compativel com JWT. O scanner esta corretamente detectando o que existe.

**Uso correto:** o relatorio serve como **inventario de cripto** (CBOM), nao como julgamento.
A lib e um ativo; saber que ela existe e a informacao util.

---

## Repo 2 — pyjwt (Python)

**Tamanho:** ~5 MB, ~30 arquivos Python.
**Funcao:** Biblioteca canonica de JWT no ecossistema Python.

### Distribuicao

| Regra | Severidade | Ocorrencias | Significado |
|-------|-----------|-------------|-------------|
| QSC-002 | CRITICAL | 60+ | ECDSA em `algorithms.py`, `api_jwk.py`, `utils.py` |
| QSC-001 | CRITICAL | 13+ | RSA nos mesmos arquivos |
| QSC-022 | CRITICAL | 2 | JWT assinado com RSA |
| QSC-021 | MEDIUM | 2 | JWT com HMAC simetrico |
| QSC-020 | CRITICAL | 2 | JWT com algoritmo `none` |

### Onde disparou

- `jwt/algorithms.py` — implementacao de todos os algoritmos
- `jwt/api_jwk.py` — parsing de JWK
- `jwt/api_jws.py` — assinatura
- `jwt/utils.py` — conversao de chaves

### Interpretacao

**Mesmo caso do node-jsonwebtoken.** pyjwt implementa RSA/ECDSA/HMAC por design.

O `QSC-020` (algoritmo `none`) dispara em
`raise InvalidKeyError('When alg = "none", key value must be None.')` —
a lib **rejeita** `none` corretamente, mas o pattern regex casa com a string.

**Isso e um falso positivo estrutural.**

---

## Limitacao conhecida (documentada honestamente)

O scanner atual **nao distingue**:

1. **Biblioteca que implementa** suporte a RSA (obrigacao) — ex: pyjwt
2. **Aplicacao que usa** RSA (risco) — ex: o servico que importa pyjwt

Resultado: relatorios de bibliotecas criptograficas sao **inflados**.

### Impacto pratico

| Cenario | Impacto |
|---------|---------|
| Escanear uma **aplicacao** (nao biblioteca) | Findings sao reais e acionaveis |
| Escanear uma **biblioteca** cripto | Findings sao reais mas esperados |
| Escanear monorepo com vendor/ | Findings duplicados |

### Roadmap (proximas versoes)

- [ ] **Deduplicacao por arquivo+linha** — hoje o mesmo finding pode aparecer 2x
- [ ] **Exclusao de diretorios** (`node_modules`, `vendor`, `.venv`) por default
- [ ] **Deteccao de lib-mode** — heuristica: se o arquivo exporta uma funcao que
      implementa o algoritmo, e "suporte"; se apenas chama, e "uso"
- [ ] **Detector de regex-comment** — ignorar strings em mensagens de erro
      (`raise InvalidKeyError("...RSA...")`)

### Mitigacao imediata

Enquanto o tuning nao chega, o usuario pode:

```bash
# Excluir diretorios de teste e vendor
qsec scan ./src --exclude "**/test/**,**/vendor/**,**/node_modules/**"

# Escanear apenas o codigo da aplicacao (nao libs)
qsec scan ./src/app --format text
```

---

## Conclusao

**O scanner detecta criptografia classica em codigo-fonte real, em 2 linguagens.**
Os 87 findings refletem o que existe no codigo (RSA, ECDSA), nao falhas de seguranca.

**O scanner precisa de tuning para uso enterprise.** Hoje nao distingue bibliotecas de
aplicacoes, e isso infla relatorios. Documentado como limitacao publica, com roadmap.

**O CBOM faz sentido.** Mesmo com falsos positivos, o inventario e util: um CISO
quer saber *onde* RSA aparece, nao apenas *se* aparece.

---

## Proximos repos para benchmark

- [ ] `openssl/openssl` (C, ~500k linhas) — teste de escala
- [ ] `django/django` (Python, framework) — teste de aplicacao real
- [ ] `spring-projects/spring-security` (Java) — language adapter JCE
- [ ] `kubernetes/kubernetes` (Go, ~5M linhas) — teste de performance
- [ ] `apache/kafka` (Java + Scala) — teste multi-linguagem

---

**Gerado em:** 2026-09-28 19:22:05
**Ferramenta:** QSEC v3.3.0 (OmniUil AI)
**Repo:** github.com/Uilcol/omniuil-ai
