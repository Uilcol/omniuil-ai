#!/bin/bash
# OmniUil AI — Verificador de Integridade de Release
set -e
BINARY="${1:-./omniuil-ai}"
SIG_FILE="${2:-./omniuil-ai.sig}"
PUBKEY_FILE="${3:-./omniuil-ai.pub}"
echo "⚡ OmniUil AI — Verificação de Integridade"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for f in "$BINARY" "$SIG_FILE" "$PUBKEY_FILE"; do
    if [ ! -f "$f" ]; then echo "❌ Arquivo não encontrado: $f"; exit 1; fi
done
SHA=$(sha256sum "$BINARY" | cut -d" " -f1)
echo "🔍 SHA-256: $SHA"
if command -v openssl &>/dev/null; then
    openssl pkeyutl -verify -pubin -inkey "$PUBKEY_FILE"         -sigfile "$SIG_FILE" -in <(echo -n "$SHA") 2>/dev/null     && echo "✅ Assinatura válida — binário autêntico OmniUil AI"     || { echo "❌ ASSINATURA INVÁLIDA — NÃO INSTALE"; exit 1; }
else
    echo "⚠️  OpenSSL não encontrado — instale com: sudo apt install openssl"
fi
