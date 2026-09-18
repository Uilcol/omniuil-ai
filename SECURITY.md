# Security Policy — OmniUil AI

## Verificação de Integridade dos Releases

Todo release oficial é assinado com Ed25519 (não RSA — irônico usar RSA
em um scanner PQC). Antes de instalar qualquer binário:

```bash
./scripts/verify-release.sh ./omniuil-ai ./omniuil-ai.sig ./omniuil-ai.pub
```

## Chave Pública de Assinatura (Ed25519)
MCowBQYDK2VwAyEAsg5U31BiVAMiYNV+cK1Ybd6SRWX79K2sTdVu0VnEkME=


Verificar independentemente: qualquer binário que falhar nessa verificação
foi modificado e NÃO deve ser instalado.

## Reportar Vulnerabilidades (Responsible Disclosure)

**Não abra issue pública.** Envie para omniuil.ai@gmail.com
com assunto [SECURITY]. Respondemos em até 48h.

Seguimos coordinated disclosure: 90 dias para remediação antes
de divulgação pública.

## Proteções Implementadas

| Área | Proteção |
|------|----------|
| Engine Rust | `#![forbid(unsafe_code)]` |
| Tokens de API | HMAC-SHA3-256 |
| Licenças | Ed25519 (não RSA) |
| CORS | Allowlist explícita |
| Agentes IA | Sem eval(), sem shell=True |
| Audit log | INSERT only, imutável |
| Score | 100/100 (41 verificações — set/2026) |

## Licenciamento e Uso

- `qsec-rust`: Apache 2.0 — livre para qualquer uso
- `qsec-enterprise` + `qsec-agents`: Licença comercial

Redistribuição modificada que remove avisos de licença é violação
contratual sujeita a DMCA takedown e ação judicial.
