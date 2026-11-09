"""Input validation for user submissions and tool arguments."""
from __future__ import annotations

import unicodedata

from pydantic import BaseModel, Field, field_validator

from config.constants import MAX_INPUT_LENGTH, SUPPORTED_LANGUAGES

INPUT_MODES = ("auto", "url", "message")


class InvalidInputError(ValueError):
    pass


class SubmissionInput(BaseModel):
    content: str = Field(..., min_length=1, max_length=MAX_INPUT_LENGTH)
    mode: str = "auto"
    language: str = "en"
    consent_to_share: bool = True

    @field_validator("content")
    @classmethod
    def _clean_content(cls, value: str) -> str:
        value = unicodedata.normalize("NFKC", value).replace("\x00", "").strip()
        if not value:
            raise ValueError("Please paste a URL or message to investigate.")
        if len(value) > MAX_INPUT_LENGTH:
            raise ValueError(f"Input is too long. Maximum {MAX_INPUT_LENGTH} characters.")
        return value

    @field_validator("mode")
    @classmethod
    def _check_mode(cls, value: str) -> str:
        value = (value or "auto").lower()
        if value not in INPUT_MODES:
            raise ValueError(f"Unknown input mode '{value}'.")
        return value

    @field_validator("language")
    @classmethod
    def _check_language(cls, value: str) -> str:
        value = (value or "en").lower()
        if value not in SUPPORTED_LANGUAGES:
            raise ValueError(f"Unsupported language '{value}'.")
        return value


def validate_submission(content: str, mode: str = "auto", language: str = "en", consent_to_share: bool = True) -> SubmissionInput:
    try:
        return SubmissionInput(content=content, mode=mode, language=language, consent_to_share=consent_to_share)
    except Exception as exc:  # pydantic.ValidationError
        messages = []
        errors = getattr(exc, "errors", None)
        if callable(errors):
            for err in errors():
                msg = err.get("msg", "")
                messages.append(msg.replace("Value error, ", ""))
        raise InvalidInputError("; ".join(messages) or str(exc)) from exc
