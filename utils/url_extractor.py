"""Extract candidate URLs from free text (SMS, chat, email)."""
from __future__ import annotations

import re

from config.constants import MAX_URLS_PER_INVESTIGATION
from utils.security import URLValidationError, parse_url

_URL_RE = re.compile(
    r"""(?ix)
    (?:https?://|www\.)                      # scheme or www
    [^\s<>"'()\[\]{}|\\^`\u0980-\u09FF]+     # body (stop at whitespace, brackets, Bangla chars)
    """
)
# Bare domains such as bkash-offer.xyz/claim without a scheme
_BARE_DOMAIN_RE = re.compile(
    r"""(?ix)
    (?<![\w@.])
    (?:[a-z0-9-]+\.)+
    (?:com|net|org|info|biz|xyz|top|tk|ml|ga|cf|gq|buzz|click|link|live|icu|site|online|
       shop|store|app|io|co|me|bd|in|uk|us|ru|cn|pk|lk|np|
       gov\.bd|com\.bd|net\.bd|org\.bd|edu\.bd|ac\.bd)
    (?:/[^\s<>"'()\[\]{}|\\^`\u0980-\u09FF]*)?
    (?![\w.])
    """
)
_TRAILING_PUNCT = ".,;:!?।"


def _clean(candidate: str) -> str:
    candidate = candidate.strip().rstrip(_TRAILING_PUNCT)
    while candidate and candidate[-1] in ")]}" and candidate.count(candidate[-1]) > candidate.count({")": "(", "]": "[", "}": "{"}[candidate[-1]]):
        candidate = candidate[:-1]
    return candidate


def extract_urls(text: str, limit: int = MAX_URLS_PER_INVESTIGATION) -> dict:
    """Return validated URLs plus any candidates that were rejected.

    Result keys: ``urls`` (normalized, deduplicated, capped), ``rejected``
    (candidate -> reason) and ``truncated`` (True if more than ``limit`` were found).
    """
    if not text:
        return {"urls": [], "rejected": {}, "truncated": False}

    candidates: list[str] = []
    for match in _URL_RE.finditer(text):
        candidates.append(_clean(match.group(0)))
    for match in _BARE_DOMAIN_RE.finditer(text):
        cleaned = _clean(match.group(0))
        if not any(cleaned in c for c in candidates):
            candidates.append(cleaned)

    urls: list[str] = []
    rejected: dict[str, str] = {}
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parsed = parse_url(candidate)
        except URLValidationError as exc:
            rejected[candidate] = str(exc)
            continue
        if parsed.normalized in seen:
            continue
        seen.add(parsed.normalized)
        urls.append(parsed.normalized)

    truncated = len(urls) > limit
    return {"urls": urls[:limit], "rejected": rejected, "truncated": truncated}
