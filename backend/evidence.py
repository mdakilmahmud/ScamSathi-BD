"""Normalized evidence structure shared by every integration and the risk engine."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from config.constants import (
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_NONE,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_NOT_CONFIGURED,
    STATUS_NOT_FOUND,
    STATUS_SKIPPED,
    STATUS_UNAVAILABLE,
)

SOURCE_LABELS = {
    "safe_browsing": "Google Safe Browsing",
    "virustotal": "VirusTotal",
    "urlhaus": "URLhaus",
    "domain": "Domain analysis",
    "message": "Message analysis",
}

EVIDENCE_TYPES = {
    "safe_browsing": "Phishing / Malware list",
    "virustotal": "Multi-engine reputation",
    "urlhaus": "Malware distribution",
    "domain": "Domain features",
    "message": "Text indicators",
}

SEVERITY_ORDER = {SEVERITY_NONE: 0, SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2, SEVERITY_HIGH: 3}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Evidence(BaseModel):
    source_key: str
    source: str
    evidence_type: str
    target: str = ""
    status: str = STATUS_COMPLETED
    severity: str = SEVERITY_NONE
    result: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    checked_at: str = Field(default_factory=utc_now_iso)
    duration_ms: int = 0

    @classmethod
    def build(cls, source_key: str, target: str, status: str, severity: str, result: str, details: dict | None = None, duration_ms: int = 0) -> "Evidence":
        return cls(
            source_key=source_key,
            source=SOURCE_LABELS.get(source_key, source_key),
            evidence_type=EVIDENCE_TYPES.get(source_key, "Other"),
            target=target,
            status=status,
            severity=severity,
            result=result,
            details=details or {},
            duration_ms=duration_ms,
        )

    @classmethod
    def not_configured(cls, source_key: str, target: str = "") -> "Evidence":
        return cls.build(source_key, target, STATUS_NOT_CONFIGURED, SEVERITY_NONE, f"{SOURCE_LABELS.get(source_key, source_key)} is not configured (missing API key).")

    @classmethod
    def unavailable(cls, source_key: str, target: str, reason: str, duration_ms: int = 0) -> "Evidence":
        return cls.build(source_key, target, STATUS_UNAVAILABLE, SEVERITY_NONE, f"Unavailable: {reason}", {"reason": reason}, duration_ms)

    @classmethod
    def failed(cls, source_key: str, target: str, reason: str, duration_ms: int = 0) -> "Evidence":
        return cls.build(source_key, target, STATUS_FAILED, SEVERITY_NONE, f"Failed: {reason}", {"reason": reason}, duration_ms)

    @classmethod
    def skipped(cls, source_key: str, target: str, reason: str) -> "Evidence":
        return cls.build(source_key, target, STATUS_SKIPPED, SEVERITY_NONE, f"Skipped: {reason}", {"reason": reason})

    @property
    def ran(self) -> bool:
        """True when the provider actually answered (match or no match)."""
        return self.status in (STATUS_COMPLETED, STATUS_NOT_FOUND)

    @property
    def is_positive(self) -> bool:
        return self.ran and self.severity != SEVERITY_NONE

    def for_model(self) -> dict:
        """Compact, sanitized view handed back to the LLM as a tool result."""
        return {
            "source": self.source,
            "target": self.target,
            "status": self.status,
            "severity": self.severity,
            "result": self.result,
            "details": _truncate(self.details),
        }


def _truncate(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "…"
    if isinstance(value, dict):
        return {str(k)[:60]: _truncate(v, depth + 1) for k, v in list(value.items())[:25]}
    if isinstance(value, list):
        return [_truncate(v, depth + 1) for v in value[:15]]
    if isinstance(value, str):
        return value if len(value) <= 300 else value[:300] + "…"
    return value


def status_label(status: str) -> str:
    return {
        STATUS_COMPLETED: "Completed",
        STATUS_NOT_FOUND: "Completed — no match",
        STATUS_UNAVAILABLE: "Unavailable",
        STATUS_FAILED: "Failed",
        STATUS_NOT_CONFIGURED: "Not configured",
        STATUS_SKIPPED: "Skipped",
    }.get(status, status)
