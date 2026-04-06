"""
QSEC LLM Provider Abstraction Layer  v3.2.1
=============================================
FIX HIGH   GroqProvider._flatten: tool_result descartado → loop de agentes quebrado
FIX HIGH   GroqProvider._flatten: join(" ") → corrupção de conteúdo multiparte
FIX HIGH   GeminiProvider: history[:-1] com lista vazia → IndexError
FIX MEDIUM OllamaProvider: sem timeout na inferência → hang infinito
FIX MEDIUM GeminiProvider: API key em tracebacks de importação
FIX MEDIUM OpenAIProvider: tool_use perde tool_call_id → ferramenta desconectada
FIX MEDIUM Singleton não invalidado ao trocar LLM_PROVIDER em runtime
FIX LOW    OllamaProvider: sem retry se ollama acabou de iniciar
FIX LOW    BedrockProvider: sem aviso de região inválida
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass

log = logging.getLogger("qsec.llm")


# ── Tipos normalizados ────────────────────────────────────────────────────────

@dataclass
class ToolCall:
    id:     str
    name:   str
    inputs: dict


@dataclass
class LLMResponse:
    text:         str
    tool_calls:   list
    stop_reason:  str
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


# ── Interface base com utilitário de blocos ───────────────────────────────────

class LLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse: ...

    @staticmethod
    def _iter_blocks(content):
        """
        Itera blocos de conteúdo de forma segura.
        Aceita str, list[dict] ou list[objeto SDK Anthropic].
        Retorna sempre dicts com chave 'type'.
        """
        if isinstance(content, str):
            yield {"type": "text", "text": content}
            return
        if not isinstance(content, list):
            return
        for b in content:
            if isinstance(b, dict):
                yield b
            elif hasattr(b, "type"):
                t = b.type
                if t == "text":
                    yield {"type": "text", "text": b.text}
                elif t == "tool_use":
                    yield {"type": "tool_use", "id": b.id,
                           "name": b.name, "input": b.input}
                elif t == "tool_result":
                    yield {"type": "tool_result",
                           "tool_use_id": b.tool_use_id,
                           "content": b.content}


# ── Anthropic ─────────────────────────────────────────────────────────────────

class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self):
        import anthropic as _a
        self._client = _a.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
        self._model  = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        kw = dict(model=self._model, max_tokens=max_tokens,
                  system=system, messages=messages)
        if tools:
            kw["tools"] = tools
        r = self._client.messages.create(**kw)
        text, tcs = "", []
        for b in r.content:
            if b.type == "text":
                text += b.text
            elif b.type == "tool_use":
                tcs.append(ToolCall(id=b.id, name=b.name, inputs=b.input))
        return LLMResponse(text=text, tool_calls=tcs,
                           stop_reason=r.stop_reason or "end_turn",
                           input_tokens=r.usage.input_tokens,
                           output_tokens=r.usage.output_tokens)


# ── Helpers OpenAI-compat (shared by Ollama, OpenAI, Groq) ───────────────────

def _tools_openai(tools):
    return [{"type": "function", "function": {
        "name": t["name"], "description": t.get("description",""),
        "parameters": t.get("input_schema", {"type":"object","properties":{}})
    }} for t in tools]


def _flatten_openai(provider_iter_blocks, messages, system):
    """
    FIX HIGH (Groq/OpenAI): tool_result era descartado → agora role=tool.
    FIX HIGH: join(" ") substituído por join("\\n") — conteúdo multiparte preservado.
    FIX MEDIUM: tool_use preserva id para rastreamento correto.
    """
    out = [{"role": "system", "content": system}]
    for m in messages:
        texts, tcalls, tresults = [], [], []
        for blk in provider_iter_blocks(m["content"]):
            btype = blk.get("type","")
            if btype == "text":
                texts.append(blk.get("text",""))
            elif btype == "tool_use":
                tcalls.append({
                    "id": blk.get("id", f"tc_{int(time.time())}"),
                    "type": "function",
                    "function": {
                        "name": blk.get("name",""),
                        "arguments": json.dumps(blk.get("input",{}))
                    }
                })
            elif btype == "tool_result":
                cont = blk.get("content","")
                if isinstance(cont, list):
                    cont = "\n".join(b.get("text","") for b in cont
                                     if isinstance(b,dict) and b.get("type")=="text")
                tresults.append({
                    "role": "tool",
                    "tool_call_id": blk.get("tool_use_id","0"),
                    "content": str(cont)
                })
        if tcalls:
            out.append({"role":"assistant",
                        "content": "\n".join(texts) or None,
                        "tool_calls": tcalls})
            out.extend(tresults)
        elif tresults:
            out.extend(tresults)
        elif texts:
            out.append({"role": m["role"], "content": "\n".join(texts)})
    return out


# ── Ollama ────────────────────────────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self):
        self._base    = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self._model   = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
        self._timeout = int(os.environ.get("OLLAMA_TIMEOUT", "180"))
        self._connect_with_retry()

    def _connect_with_retry(self, attempts=3, delay=2.0):
        """FIX LOW: 3 tentativas com backoff."""
        last = None
        for i in range(attempts):
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(f"{self._base}/api/tags"), timeout=5
                ): return
            except Exception as e:
                last = e
                if i < attempts - 1:
                    time.sleep(delay)
        raise RuntimeError(
            f"Ollama não encontrado em {self._base} após {attempts} tentativas.\n"
            "Instale: curl -fsSL https://ollama.com/install.sh | sh\n"
            f"Modelo:  ollama pull {self._model}\n"
            f"Erro: {last}"
        )

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        payload = {
            "model":    self._model,
            "messages": _flatten_openai(self._iter_blocks, messages, system),
            "stream":   False,
            "options":  {"num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = _tools_openai(tools)
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            f"{self._base}/api/chat", data=data,
            headers={"Content-Type":"application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Ollama HTTP {e.code}: {e.read().decode()[:300]}")
        except TimeoutError:
            raise RuntimeError(
                f"Ollama timeout após {self._timeout}s. "
                "Aumente OLLAMA_TIMEOUT ou use um modelo menor."
            )
        msg = body.get("message", {})
        text, tcs = msg.get("content","") or "", []
        for tc in msg.get("tool_calls", []):
            fn   = tc.get("function",{})
            args = fn.get("arguments",{})
            if isinstance(args, str):
                try:    args = json.loads(args)
                except: args = {}
            tcs.append(ToolCall(
                id=tc.get("id", f"tc_{int(time.time())}"),
                name=fn.get("name",""), inputs=args
            ))
        stop = "tool_use" if tcs else "end_turn"
        if body.get("done_reason") == "length": stop = "max_tokens"
        return LLMResponse(text=text, tool_calls=tcs, stop_reason=stop,
                           input_tokens=body.get("prompt_eval_count",0),
                           output_tokens=body.get("eval_count",0))


# ── OpenAI ────────────────────────────────────────────────────────────────────

class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self):
        try:   import openai as _o
        except ImportError: raise ImportError("pip install openai>=1.30.0")
        self._client = _o.OpenAI(api_key=os.environ.get("OPENAI_API_KEY",""))
        self._model  = os.environ.get("OPENAI_MODEL","gpt-4o")

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        kw = dict(model=self._model,
                  messages=_flatten_openai(self._iter_blocks, messages, system),
                  max_tokens=max_tokens)
        if tools:
            kw["tools"] = _tools_openai(tools)
            kw["tool_choice"] = "auto"
        r   = self._client.chat.completions.create(**kw)
        msg = r.choices[0].message
        text, tcs = msg.content or "", []
        for tc in (msg.tool_calls or []):
            try:    args = json.loads(tc.function.arguments)
            except: args = {}
            tcs.append(ToolCall(id=tc.id, name=tc.function.name, inputs=args))
        stop = "tool_use" if tcs else "end_turn"
        if r.choices[0].finish_reason == "length": stop = "max_tokens"
        return LLMResponse(text=text, tool_calls=tcs, stop_reason=stop,
                           input_tokens=r.usage.prompt_tokens,
                           output_tokens=r.usage.completion_tokens)


# ── Gemini ────────────────────────────────────────────────────────────────────

class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self):
        try:   import google.generativeai as _g
        except ImportError: raise ImportError("pip install google-generativeai>=0.5.0")
        self._genai      = _g
        self._model_name = os.environ.get("GEMINI_MODEL","gemini-1.5-pro")
        self._api_key    = os.environ.get("GEMINI_API_KEY","")
        # FIX MEDIUM: configure adiado — chave não aparece em tracebacks de import

    def _get_model(self, tools=None):
        self._genai.configure(api_key=self._api_key)
        gemini_tools = None
        if tools:
            from google.generativeai.types import Tool, FunctionDeclaration
            gemini_tools = []
            for t in tools:
                props    = t.get("input_schema",{}).get("properties",{})
                required = t.get("input_schema",{}).get("required",[])
                params   = {"type":"object","properties":{
                    k:{"type":v.get("type","string"),"description":v.get("description","")}
                    for k,v in props.items()
                }}
                if required: params["required"] = required
                gemini_tools.append(Tool(function_declarations=[
                    FunctionDeclaration(name=t["name"],
                                        description=t.get("description",""),
                                        parameters=params)
                ]))
        return self._genai.GenerativeModel(
            self._model_name, tools=gemini_tools,
            generation_config=self._genai.GenerationConfig(max_output_tokens=4096)
        )

    def _build_history_and_prompt(self, messages, system):
        """
        FIX HIGH: history[:-1] com lista vazia causava IndexError.
        Lógica reescrita: itera a lista e separa explicitamente.
        """
        history = []
        for m in messages:
            role  = "user" if m["role"] == "user" else "model"
            parts = []
            for blk in self._iter_blocks(m["content"]):
                btype = blk.get("type","")
                if btype == "text" and blk.get("text"):
                    parts.append(blk["text"])
                elif btype in ("tool_use","tool_result"):
                    parts.append(json.dumps({k:v for k,v in blk.items() if k!="type"}))
            if parts:
                history.append({"role": role, "parts": parts})

        # Separar último user turn como prompt
        if history and history[-1]["role"] == "user":
            prompt  = f"System: {system}\n\n" + "\n".join(history[-1]["parts"])
            history = history[:-1]
        else:
            prompt  = f"System: {system}\n\ncontinue"

        return history, prompt

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        model = self._get_model(tools)
        history, prompt = self._build_history_and_prompt(messages, system)
        chat = model.start_chat(history=history)
        r    = chat.send_message(prompt)
        text, tcs = "", []
        for part in r.parts:
            if hasattr(part,"text") and part.text:
                text += part.text
            elif hasattr(part,"function_call") and part.function_call:
                fc = part.function_call
                tcs.append(ToolCall(
                    id=f"gemini_{int(time.time())}_{fc.name}",
                    name=fc.name, inputs=dict(fc.args)
                ))
        return LLMResponse(text=text, tool_calls=tcs,
                           stop_reason="tool_use" if tcs else "end_turn")


# ── Groq ──────────────────────────────────────────────────────────────────────

class GroqProvider(LLMProvider):
    name = "groq"

    def __init__(self):
        try:   from groq import Groq
        except ImportError: raise ImportError("pip install groq>=0.9.0")
        self._client = Groq(api_key=os.environ.get("GROQ_API_KEY",""))
        self._model  = os.environ.get("GROQ_MODEL","llama-3.1-8b-instant")

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        # FIX HIGH: _flatten_openai agora preserva tool_result como role=tool
        kw = dict(model=self._model,
                  messages=_flatten_openai(self._iter_blocks, messages, system),
                  max_tokens=max_tokens)
        if tools:
            kw["tools"] = _tools_openai(tools)
        r   = self._client.chat.completions.create(**kw)
        msg = r.choices[0].message
        text, tcs = msg.content or "", []
        for tc in (msg.tool_calls or []):
            try:    args = json.loads(tc.function.arguments)
            except: args = {}
            tcs.append(ToolCall(id=tc.id, name=tc.function.name, inputs=args))
        stop = "tool_use" if tcs else "end_turn"
        if r.choices[0].finish_reason == "length": stop = "max_tokens"
        return LLMResponse(text=text, tool_calls=tcs, stop_reason=stop,
                           input_tokens=r.usage.prompt_tokens,
                           output_tokens=r.usage.completion_tokens)


# ── AWS Bedrock ───────────────────────────────────────────────────────────────

class BedrockProvider(LLMProvider):
    name = "bedrock"

    _VALID_REGIONS = {
        "us-east-1","us-west-2","eu-west-1","eu-central-1",
        "ap-southeast-1","ap-northeast-1","ap-south-1",
    }

    def __init__(self):
        try:   import boto3
        except ImportError: raise ImportError("pip install boto3>=1.34.0")
        region = os.environ.get("AWS_DEFAULT_REGION","us-east-1")
        # FIX LOW: aviso de região provavelmente sem o modelo
        if region not in self._VALID_REGIONS:
            log.warning("BedrockProvider: região '%s' pode não ter Claude. "
                        "Regiões válidas: %s", region, ", ".join(sorted(self._VALID_REGIONS)))
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model  = os.environ.get("BEDROCK_MODEL_ID",
                                      "anthropic.claude-3-5-sonnet-20241022-v2:0")

    def _normalize(self, messages):
        """Converte objetos SDK para dicts puros."""
        out = []
        for m in messages:
            content = [b for b in self._iter_blocks(m["content"])]
            if content:
                out.append({"role": m["role"], "content": content})
        return out

    def chat(self, messages, system, tools=None, max_tokens=4096) -> LLMResponse:
        body = {"anthropic_version":"bedrock-2023-05-31",
                "max_tokens":max_tokens, "system":system,
                "messages":self._normalize(messages)}
        if tools: body["tools"] = tools
        resp = self._client.invoke_model(
            modelId=self._model, contentType="application/json",
            accept="application/json", body=json.dumps(body)
        )
        r = json.loads(resp["body"].read())
        text, tcs = "", []
        for blk in r.get("content",[]):
            if blk.get("type") == "text":   text += blk.get("text","")
            elif blk.get("type") == "tool_use":
                tcs.append(ToolCall(id=blk.get("id","0"),
                                    name=blk.get("name",""),
                                    inputs=blk.get("input",{})))
        return LLMResponse(text=text, tool_calls=tcs,
                           stop_reason=r.get("stop_reason","end_turn"),
                           input_tokens=r.get("usage",{}).get("input_tokens",0),
                           output_tokens=r.get("usage",{}).get("output_tokens",0))


# ── Factory ───────────────────────────────────────────────────────────────────

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "ollama":    OllamaProvider,
    "openai":    OpenAIProvider,
    "gemini":    GeminiProvider,
    "groq":      GroqProvider,
    "bedrock":   BedrockProvider,
}

_instance:      LLMProvider | None = None
_instance_name: str | None         = None


def get_provider() -> LLMProvider:
    """
    Retorna instância singleton do provedor LLM configurado via LLM_PROVIDER.
    FIX MEDIUM: reinicializa se LLM_PROVIDER mudar em runtime.
    """
    global _instance, _instance_name
    current = os.environ.get("LLM_PROVIDER", "anthropic").lower()
    if _instance is not None and _instance_name == current:
        return _instance
    cls = _PROVIDERS.get(current)
    if cls is None:
        raise ValueError(
            f"LLM_PROVIDER='{current}' inválido. "
            f"Disponíveis: {', '.join(_PROVIDERS)}"
        )
    _instance      = cls()
    _instance_name = current
    model = getattr(_instance,"_model",getattr(_instance,"_model_name","—"))
    log.info("LLM provider: %s (%s)", current.upper(), model)
    print(f"[QSEC] LLM Provider: {current.upper()}  model: {model}")
    return _instance


def reset_provider():
    """Força reinicialização — útil em testes."""
    global _instance, _instance_name
    _instance = _instance_name = None
