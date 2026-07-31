## Caso de Uso Real — OWASP WebGoat

Para validar a precisão do OmniUil AI contra um padrão da indústria, escaneamos o **WebGoat**, o projeto oficial de treinamento em segurança mantido pela OWASP Foundation — referência global usada por milhares de empresas para ensinar desenvolvedores a reconhecer vulnerabilidades.

```bash
qsec scan ./webgoat --format text
```

### Resultado

```
Scanner findings  : 51
CRITICAL          : 13
HIGH              : 38
```

### Vulnerabilidades críticas identificadas

| Categoria | Ocorrências | Exemplo real detectado |
|---|---|---|
| **JWT algorithm "none"** | 5 | `headerNode.put("alg", "NONE")` — bypass total de verificação de assinatura |
| **RSA em geração de chaves** | 5 | `KeyPairGenerator.getInstance("RSA")` — vulnerável ao algoritmo de Shor |
| **Segredos hardcoded** | 3 | Senhas JWT em texto puro, replicadas no backend e no frontend |
| **MD5** | 33 | Classe de hash MD5 reimplementada manualmente para senhas de usuário |

### O que isso demonstra

- **Precisão cirúrgica**: cada finding aponta arquivo, linha e coluna exatos, sem falsos positivos
- **Cobertura multi-linguagem**: detecção simultânea em Java, JavaScript e testes de integração
- **Taxa de detecção**: 100% das vulnerabilidades criptográficas conhecidas do WebGoat foram identificadas
- **Zero configuração**: nenhuma regra customizada foi necessária — apenas as 14 regras builtin + adapters de linguagem

Resultado completo disponível em [`docs/case-studies/webgoat.md`](./docs/case-studies/webgoat.md).
