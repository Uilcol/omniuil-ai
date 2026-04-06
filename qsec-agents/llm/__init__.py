"""
QSEC LLM Provider Abstraction Layer
====================================
Troca de provedor via variável de ambiente — zero alteração no código dos agentes.

Uso:
    export LLM_PROVIDER=ollama          # local, gratuito, privado
    export LLM_PROVIDER=openai          # GPT-4o
    export LLM_PROVIDER=gemini          # Google Gemini
    export LLM_PROVIDER=groq            # Groq (free tier generoso)
    export LLM_PROVIDER=bedrock         # AWS Bedrock
    export LLM_PROVIDER=anthropic       # padrão atual (Claude)
"""

from .provider import get_provider, LLMProvider, LLMResponse

__all__ = ["get_provider", "LLMProvider", "LLMResponse"]
