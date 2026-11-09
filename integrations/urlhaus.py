"""URLhaus (abuse.ch) integration — malware-distribution intelligence only.

Docs: https://urlhaus-api.abuse.ch/
URLhaus is not a phishing database. A hit means the URL was reported for
malware distribution; no hit means "not in this dataset", not "safe".
"""
from __future__ import annotations

from backend.evidence import Evidence
from config.constants import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_NONE, STATUS_COMPLETED, STATUS_NOT_FOUND
from config import settings as config_settings
from integrations import http_client
from utils.security import URLValidationError, parse_url

ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
SOURCE = "urlhaus"


def parse_response(url: str, body: dict | None, duration_ms: int = 0) -> Evidence:
    body = body or {}
    query_status = body.get("query_status", "")
    if query_status == "no_results":
        return Evidence.build(SOURCE, url, STATUS_NOT_FOUND, SEVERITY_NONE, "Not found in the URLhaus malware-distribution dataset.", {"query_status": query_status}, duration_ms)
    if query_status != "ok":
        return Evidence.unavailable(SOURCE, url, f"unexpected query_status '{query_status or 'empty'}'", duration_ms)
    url_status = body.get("url_status", "unknown")
    threat = body.get("threat", "unknown")
    tags = body.get("tags") or []
    severity = SEVERITY_HIGH if url_status == "online" else SEVERITY_MEDIUM
    details = {
        "query_status": query_status,
        "url_status": url_status,
        "threat": threat,
        "tags": tags,
        "date_added": body.get("date_added"),
        "blacklists": body.get("blacklists"),
        "reference": body.get("urlhaus_reference"),
    }
    return Evidence.build(SOURCE, url, STATUS_COMPLETED, severity, f"Reported to URLhaus as {threat} ({url_status}).", details, duration_ms)


def check_url(url: str, auth_key: str | None = None) -> Evidence:
    auth_key = auth_key if auth_key is not None else config_settings.settings.urlhaus_auth_key
    try:
        parsed = parse_url(url)
    except URLValidationError as exc:
        return Evidence.failed(SOURCE, url, f"invalid URL: {exc}")
    if not auth_key or auth_key.startswith("your_"):
        return Evidence.not_configured(SOURCE, parsed.normalized)
    headers = {"Auth-Key": auth_key}
    result = http_client.request("POST", ENDPOINT, headers=headers, data={"url": parsed.normalized})
    if not result.ok:
        if result.status_code in (401, 403):
            return Evidence.unavailable(SOURCE, parsed.normalized, "authentication required or rejected (set URLHAUS_AUTH_KEY)", result.duration_ms)
        if result.rate_limited:
            return Evidence.unavailable(SOURCE, parsed.normalized, "rate limit exceeded", result.duration_ms)
        return Evidence.unavailable(SOURCE, parsed.normalized, result.error or "unknown error", result.duration_ms)
    return parse_response(parsed.normalized, result.json if isinstance(result.json, dict) else {}, result.duration_ms)
