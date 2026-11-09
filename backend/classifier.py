"""Identify what kind of content was submitted (URL / message / email / mixed)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from utils.security import URLValidationError, parse_url
from utils.url_extractor import extract_urls

INPUT_TYPE_URL = "URL"
INPUT_TYPE_MESSAGE = "Message"
INPUT_TYPE_EMAIL = "Email"
INPUT_TYPE_MIXED = "Mixed"

_EMAIL_HEADER_RE = re.compile(r"(?im)^(from|to|subject|reply-to|cc|date)\s*:")
_EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_GREETING_RE = re.compile(r"(?im)^(dear|hello|hi|প্রিয়)\b")
_URL_SHAPED_RE = re.compile(r"(?i)^(?:[a-z][a-z0-9+.-]*:|[^\s]+\.[^\s]+$)")


@dataclass
class Classification:
    input_type: str
    urls: list[str] = field(default_factory=list)
    rejected_urls: dict = field(default_factory=dict)
    has_message_text: bool = False
    primary_target: str = ""
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "input_type": self.input_type,
            "urls": list(self.urls),
            "rejected_urls": dict(self.rejected_urls),
            "has_message_text": self.has_message_text,
            "primary_target": self.primary_target,
            "reasons": list(self.reasons),
        }


def _is_single_url(text: str) -> bool:
    if any(ch.isspace() for ch in text):
        return False
    try:
        parse_url(text)
        return True
    except URLValidationError:
        return False


def classify_input(content: str, mode: str = "auto") -> Classification:
    text = content.strip()
    reasons: list[str] = []

    if mode == "url":
        try:
            parsed = parse_url(text)
        except URLValidationError as exc:
            raise URLValidationError(f"Invalid URL: {exc}") from exc
        return Classification(INPUT_TYPE_URL, [parsed.normalized], {}, False, parsed.host, ["User selected URL scan"])

    extraction = extract_urls(text)
    urls = extraction["urls"]
    rejected = extraction["rejected"]

    if mode == "message":
        reasons.append("User selected message scan")
        return Classification(INPUT_TYPE_MESSAGE, urls, rejected, True, _target_from_text(text), reasons)

    if _is_single_url(text):
        parsed = parse_url(text)
        return Classification(INPUT_TYPE_URL, [parsed.normalized], {}, False, parsed.host, ["Input is a single URL"])

    if len(text.split()) == 1 and not urls and _URL_SHAPED_RE.match(text):
        # Something URL-shaped that failed validation (e.g. javascript:, file:, localhost)
        if rejected:
            reason = next(iter(rejected.values()))
        else:
            try:
                parse_url(text)
                reason = "URL could not be processed."
            except URLValidationError as exc:
                reason = str(exc)
        raise URLValidationError(f"Invalid URL: {reason}")

    looks_like_email = bool(_EMAIL_HEADER_RE.search(text)) or (
        bool(_EMAIL_ADDR_RE.search(text)) and (bool(_GREETING_RE.search(text)) or len(text) > 300)
    )
    if looks_like_email:
        reasons.append("Email-like headers or address plus greeting detected")
        return Classification(INPUT_TYPE_EMAIL, urls, rejected, True, _target_from_text(text, urls), reasons)

    if urls:
        reasons.append(f"Message text containing {len(urls)} URL(s)")
        return Classification(INPUT_TYPE_MIXED, urls, rejected, True, _target_from_text(text, urls), reasons)

    reasons.append("Free text without URLs")
    return Classification(INPUT_TYPE_MESSAGE, [], rejected, True, _target_from_text(text), reasons)


def _target_from_text(text: str, urls: list[str] | None = None) -> str:
    if urls:
        try:
            return parse_url(urls[0]).host
        except URLValidationError:
            pass
    flat = " ".join(text.split())
    return flat if len(flat) <= 60 else flat[:57] + "..."
