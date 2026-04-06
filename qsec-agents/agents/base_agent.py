"""
BaseAgent — Classe base para todos os agentes QSEC.

Totalmente independente de provedor LLM. Usa a camada de abstração
llm.provider para suportar Ollama, OpenAI, Gemini, Groq, Bedrock e Anthropic.

Troca de provedor:
    export LLM_PROVIDER=ollama      # local, grátis, privado
    export LLM_PROVIDER=openai      # GPT-4o
    export LLM_PROVIDER=groq        # grátis com Llama 3.1
    # (sem variável = anthropic, compatível com código anterior)
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

from llm.provider import get_provider, LLMProvider, LLMResponse, ToolCall
from memory.shared_memory import SharedMemory
from tools.qsec_tools import QSEC_TOOLS, execute_tool

MAX_TOKENS        = 4096
MAX_ITERATIONS    = 10
MAX_TOTAL_TOKENS  = 80_000


class BaseAgent(ABC):
    """Agente base com loop agentic completo — agnóstico de provedor LLM."""

    def __init__(self, memory: SharedMemory):
        self.memory    = memory
        self._provider: LLMProvider = get_provider()

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def system_prompt(self) -> str: ...

    @property
    def tools(self) -> list[dict]:
        return QSEC_TOOLS

    async def run(self, task: str, context: dict | None = None) -> dict:
        await self.memory.log_action(self.name, "task_started", {"task": task[:100]})

        messages        = [{"role": "user", "content": self._build_user_message(task, context)}]
        iterations      = 0
        tool_calls_made = []
        total_tokens    = 0

        while iterations < MAX_ITERATIONS:
            iterations += 1

            response: LLMResponse = self._provider.chat(
                messages=messages, system=self.system_prompt,
                tools=self.tools, max_tokens=MAX_TOKENS,
            )

            total_tokens += response.input_tokens + response.output_tokens
            if total_tokens > MAX_TOTAL_TOKENS:
                await self.memory.log_action(self.name, "token_budget_exceeded",
                    {"total": total_tokens, "limit": MAX_TOTAL_TOKENS})
                return self._result(task, tool_calls_made, iterations, False,
                    f"Token budget exceeded ({total_tokens} > {MAX_TOTAL_TOKENS})")

            messages.append(self._response_to_history(response))

            if not response.has_tool_calls:
                await self.memory.log_action(self.name, "task_completed",
                    {"iterations": iterations, "tools_used": len(tool_calls_made),
                     "provider": self._provider.name})
                return self._result(task, tool_calls_made, iterations, True, response.text)

            tool_results = []
            for tc in response.tool_calls:
                await self.memory.log_action(self.name, f"tool_call:{tc.name}",
                    {"inputs": {k: str(v)[:80] for k, v in tc.inputs.items()}})
                result = execute_tool(tc.name, tc.inputs)
                tool_calls_made.append({"tool": tc.name, "inputs": tc.inputs, "result": result})
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": json.dumps(result),
                })

            messages.append({"role": "user", "content": tool_results})

        await self.memory.log_action(self.name, "max_iterations_reached", {"task": task[:80]})
        return self._result(task, tool_calls_made, iterations, False, "Max iterations reached")

    def _build_user_message(self, task: str, context: dict | None) -> str:
        msg = task
        if context:
            msg += f"\n\n<context>\n{json.dumps(context, indent=2, default=str)}\n</context>"
        return msg

    def _response_to_history(self, response: LLMResponse) -> dict:
        content = []
        if response.text:
            content.append({"type": "text", "text": response.text})
        for tc in response.tool_calls:
            content.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.inputs})
        return {"role": "assistant", "content": content or response.text or ""}

    def _result(self, task, tool_calls, iterations, success, text="") -> dict:
        return {"agent": self.name, "task": task, "result": text,
                "tool_calls": tool_calls, "iterations": iterations,
                "success": success, "provider": self._provider.name}
