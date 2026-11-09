"""Gemini client wrapper.

Exposes two narrow operations used by the agent:
  * ``generate_turn`` — one model turn with declared function tools.
  * ``generate_structured`` — JSON output validated against a Pydantic schema.
Automatic function calling in the SDK is disabled: the application validates
and executes every tool call itself.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel

from config.settings import settings


class GeminiError(RuntimeError):
    pass


@dataclass
class ToolCallRequest:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelTurn:
    text: str = ""
    function_calls: list[ToolCallRequest] = field(default_factory=list)
    raw_content: Any = None  # provider-specific content to append to the history


class ModelClient(Protocol):
    """Anything the agent can drive: Gemini, the rule-based fallback, or a test fake."""

    name: str

    def generate_turn(self, history: list[Any], tools: list[dict], system_instruction: str) -> ModelTurn: ...

    def generate_structured(self, prompt: str, schema: type[BaseModel], system_instruction: str) -> BaseModel: ...

    def user_message(self, text: str) -> Any: ...

    def tool_result_message(self, name: str, result: dict) -> Any: ...


class GeminiClient:
    name = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        from google import genai  # imported lazily so tests never need the SDK configured

        self._types = genai.types
        self._client = genai.Client(api_key=api_key or settings.gemini_api_key)
        self.model = model or settings.gemini_model

    def user_message(self, text: str):
        return self._types.Content(role="user", parts=[self._types.Part.from_text(text=text)])

    def tool_result_message(self, name: str, result: dict):
        return self._types.Content(role="user", parts=[self._types.Part.from_function_response(name=name, response={"result": result})])

    def generate_turn(self, history: list[Any], tools: list[dict], system_instruction: str) -> ModelTurn:
        types = self._types
        declarations = [types.FunctionDeclaration(**decl) for decl in tools]
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=[types.Tool(function_declarations=declarations)],
            tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="AUTO")),
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            temperature=0.2,
        )
        try:
            response = self._client.models.generate_content(model=self.model, contents=history, config=config)
        except Exception as exc:
            raise GeminiError(f"Gemini request failed: {exc.__class__.__name__}: {exc}") from exc

        candidates = response.candidates or []
        if not candidates or candidates[0].content is None:
            raise GeminiError("Gemini returned no candidates.")
        content = candidates[0].content
        calls: list[ToolCallRequest] = []
        texts: list[str] = []
        for part in content.parts or []:
            if part.function_call is not None:
                calls.append(ToolCallRequest(name=part.function_call.name or "", args=dict(part.function_call.args or {})))
            elif part.text:
                texts.append(part.text)
        return ModelTurn(text="\n".join(texts).strip(), function_calls=calls, raw_content=content)

    def generate_structured(self, prompt: str, schema: type[BaseModel], system_instruction: str) -> BaseModel:
        types = self._types
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=schema,
            temperature=0.3,
        )
        try:
            response = self._client.models.generate_content(model=self.model, contents=prompt, config=config)
        except Exception as exc:
            raise GeminiError(f"Gemini request failed: {exc.__class__.__name__}: {exc}") from exc
        parsed = getattr(response, "parsed", None)
        if isinstance(parsed, schema):
            return parsed
        text = (response.text or "").strip()
        if not text:
            raise GeminiError("Gemini returned an empty structured response.")
        try:
            return schema.model_validate(json.loads(text))
        except Exception as exc:
            raise GeminiError(f"Gemini structured output failed validation: {exc}") from exc


def ping() -> tuple[bool, str]:
    """Minimal connectivity test used by the settings page and setup phase."""
    if not settings.gemini_configured:
        return False, "GEMINI_API_KEY not configured"
    try:
        from google import genai

        client = genai.Client(api_key=settings.gemini_api_key)
        response = client.models.generate_content(model=settings.gemini_model, contents="Reply with the single word OK.")
        return True, (response.text or "").strip()[:50]
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"[:200]
