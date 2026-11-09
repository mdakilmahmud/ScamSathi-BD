"""Google Safe Browsing Lookup API (v4) integration.

Docs: https://developers.google.com/safe-browsing/v4/lookup-api
A match is positive evidence. No match only means the URL is not on the
requested lists; it is never treated as proof of safety.
"""
from __future__ import annotations

from backend.evidence import Evidence
from config.constants import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_NONE, STATUS_COMPLETED, STATUS_NOT_FOUND
from config import settings as config_settings
from integrations import http_client
from utils.security import URLValidationError, parse_url

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
HIGH_SEVERITY_THREATS = {"MALWARE", "SOCIAL_ENGINEERING"}
SOURCE = "safe_browsing"

THREAT_DESCRIPTIONS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "social engineering / phishing",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}


def build_request_body(url: str) -> dict:
    return {
        "client": {"clientId": "scamsathibd", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def parse_response(url: str, body: dict | None, duration_ms: int = 0) -> Evidence:
    matches = (body or {}).get("matches") or []
    if not matches:
        return Evidence.build(SOURCE, url, STATUS_NOT_FOUND, SEVERITY_NONE, "No matching threat found in Safe Browsing lists (not proof of safety).", {"matches": []}, duration_ms)
    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    severity = SEVERITY_HIGH if any(t in HIGH_SEVERITY_THREATS for t in threat_types) else SEVERITY_MEDIUM
    described = ", ".join(THREAT_DESCRIPTIONS.get(t, t.lower()) for t in threat_types)
    return Evidence.build(
        SOURCE, url, STATUS_COMPLETED, severity,
        f"Listed by Google Safe Browsing as {described}.",
        {"matches": [{"threatType": m.get("threatType"), "platformType": m.get("platformType")} for m in matches], "threat_types": threat_types},
        duration_ms,
    )


def check_url(url: str, api_key: str | None = None) -> Evidence:
    api_key = api_key if api_key is not None else config_settings.settings.safe_browsing_key
    try:
        parsed = parse_url(url)
    except URLValidationError as exc:
        return Evidence.failed(SOURCE, url, f"invalid URL: {exc}")
    if not api_key or api_key.startswith("your_"):
        return Evidence.not_configured(SOURCE, parsed.normalized)

    result = http_client.request("POST", ENDPOINT, params={"key": api_key}, json=build_request_body(parsed.normalized))
    if not result.ok:
        if result.rate_limited:
            return Evidence.unavailable(SOURCE, parsed.normalized, "rate limit exceeded", result.duration_ms)
        if result.status_code in (400, 401, 403):
            detail = ((result.json or {}).get("error") or {}).get("message", "") if isinstance(result.json, dict) else ""
            return Evidence.unavailable(SOURCE, parsed.normalized, f"API rejected request ({result.error}) {detail}".strip(), result.duration_ms)
        return Evidence.unavailable(SOURCE, parsed.normalized, result.error or "unknown error", result.duration_ms)
    return parse_response(parsed.normalized, result.json if isinstance(result.json, dict) else {}, result.duration_ms)
