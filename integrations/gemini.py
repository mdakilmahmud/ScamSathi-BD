"""Gemini client wrapper.

Exposes two narrow operations used by the agent:
  * ``generate_turn`` — one model turn with declared function tools.
  * ``generate_structured`` — JSON output validated against a Pydantic schema.
Automatic function calling in the SDK is disabled: the application validates
and executes every tool call itself.
"""
from __future__ import annotations

import json
import re
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


GEMINI_TIMEOUT_MS = 45_000
# Model names are retired frequently and busy models return 503/504; these are the
# only error codes for which we move on to the next configured model.
RETRY_NEXT_MODEL_CODES = {404, 429, 500, 503, 504}


def _error_code(exc: Exception) -> int | None:
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    match = re.match(r"\s*(\d{3})\b", str(exc))
    return int(match.group(1)) if match else None


class GeminiClient:
    name = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        from google import genai  # imported lazily so tests never need the SDK configured

        self._types = genai.types
        self._client = genai.Client(
            api_key=api_key or settings.gemini_api_key,
            http_options=genai.types.HttpOptions(timeout=GEMINI_TIMEOUT_MS),
        )
        self.model = model or settings.gemini_model
        self._candidates = [model] if model else settings.gemini_model_candidates
        self.model_used: str | None = None
        self.model_switches: list[str] = []

    def _thinking_config(self):
        level = (settings.gemini_thinking_level or "").strip().lower()
        if level in ("", "default", "auto"):
            return None
        return self._types.ThinkingConfig(thinking_level=level.upper())

    def _with_thinking(self, config: Any, thinking: Any):
        if thinking is None:
            return config
        if config is None:
            return self._types.GenerateContentConfig(thinking_config=thinking)
        return config.model_copy(update={"thinking_config": thinking})

    def _generate(self, contents: Any, config: Any):
        """Call generate_content, falling back to the next model only on availability errors."""
        errors: list[str] = []
        for candidate in self._candidates:
            try:
                response = self._client.models.generate_content(model=candidate, contents=contents, config=config)
                self.model_used = candidate
                if errors:
                    self.model_switches.append(f"Switched to {candidate} after: " + " | ".join(errors))
                self._candidates = [candidate, *[c for c in self._candidates if c != candidate]]
                return response
            except Exception as exc:
                errors.append(f"{candidate}: {exc.__class__.__name__}: {str(exc)[:160]}")
                if _error_code(exc) not in RETRY_NEXT_MODEL_CODES:
                    break
        raise GeminiError("Gemini request failed: " + " | ".join(errors))

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
        response = self._generate(history, config)

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
        response = self._generate(prompt, config)
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

        client = GeminiClient()
        response = client._generate("Reply with the single word OK.", None)
        return True, f"{client.model_used}: {(response.text or '').strip()[:40]}"
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"[:200]
