"""Application settings loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name, default)
    return value.strip() if value else default


def _is_placeholder(value: str) -> bool:
    return not value or value.startswith("your_")


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _env("GEMINI_MODEL", "gemini-3.5-flash-lite"))
    gemini_thinking_level: str = field(default_factory=lambda: _env("GEMINI_THINKING_LEVEL", "low"))
    gemini_fallback_models: str = field(default_factory=lambda: _env("GEMINI_FALLBACK_MODELS", "gemini-3.6-flash,gemini-3.1-flash-lite,gemini-3-flash-preview"))
    virustotal_api_key: str = field(default_factory=lambda: _env("VIRUSTOTAL_API_KEY"))
    safe_browsing_key: str = field(default_factory=lambda: _env("GOOGLE_SAFE_BROWSING_KEY"))
    urlhaus_auth_key: str = field(default_factory=lambda: _env("URLHAUS_AUTH_KEY"))
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL", "sqlite:///scamsathi.db"))
    retain_submitted_content: bool = field(
        default_factory=lambda: _env("RETAIN_SUBMITTED_CONTENT", "true").lower() in ("1", "true", "yes")
    )
    http_timeout_seconds: float = 10.0
    virustotal_poll_timeout_seconds: float = 20.0
    virustotal_poll_interval_seconds: float = 3.0

    @property
    def gemini_model_candidates(self) -> list[str]:
        """Primary model first, then fallbacks tried only on 404/429/5xx responses."""
        seen: list[str] = []
        for name in [self.gemini_model, *self.gemini_fallback_models.split(",")]:
            name = name.strip()
            if name and name not in seen:
                seen.append(name)
        return seen

    @property
    def gemini_configured(self) -> bool:
        return not _is_placeholder(self.gemini_api_key)

    @property
    def virustotal_configured(self) -> bool:
        return not _is_placeholder(self.virustotal_api_key)

    @property
    def safe_browsing_configured(self) -> bool:
        return not _is_placeholder(self.safe_browsing_key)

    @property
    def urlhaus_configured(self) -> bool:
        # abuse.ch now requires an Auth-Key for API queries.
        return not _is_placeholder(self.urlhaus_auth_key)

    def tool_availability(self) -> dict:
        return {
            "gemini": self.gemini_configured,
            "virustotal": self.virustotal_configured,
            "safe_browsing": self.safe_browsing_configured,
            "urlhaus": self.urlhaus_configured,
        }


settings = Settings()
