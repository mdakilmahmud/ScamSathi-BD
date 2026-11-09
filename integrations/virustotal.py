"""VirusTotal API v3 integration for URL reputation.

Docs: https://docs.virustotal.com/reference/overview
Flow: look up an existing URL report (GET /urls/{id}); if none exists submit
the URL (POST /urls) and poll the analysis for a bounded time.
"""
from __future__ import annotations

import base64
import time

from backend.evidence import Evidence
from config.constants import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_NONE, STATUS_COMPLETED, STATUS_NOT_FOUND
from config import settings as config_settings
from integrations import http_client
from utils.security import URLValidationError, parse_url

BASE = "https://www.virustotal.com/api/v3"
SOURCE = "virustotal"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "accept": "application/json"}


def severity_from_stats(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 5:
        return SEVERITY_HIGH
    if malicious >= 2:
        return SEVERITY_MEDIUM
    if malicious == 1 or suspicious >= 2:
        return SEVERITY_LOW
    return SEVERITY_NONE


def parse_stats(url: str, stats: dict, extra: dict | None = None, duration_ms: int = 0, analysis_status: str = "completed") -> Evidence:
    stats = {k: int(v or 0) for k, v in (stats or {}).items() if isinstance(v, (int, float)) or str(v).isdigit()}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    severity = severity_from_stats(stats)
    details = {"stats": stats, "engines_total": total, "analysis_status": analysis_status}
    if extra:
        details.update(extra)
    if malicious or suspicious:
        result = f"{malicious} engine(s) flagged malicious and {suspicious} suspicious out of {total}."
        return Evidence.build(SOURCE, url, STATUS_COMPLETED, severity, result, details, duration_ms)
    result = f"No engine flagged this URL ({harmless} harmless, {undetected} undetected of {total}). Not proof of safety."
    return Evidence.build(SOURCE, url, STATUS_NOT_FOUND, SEVERITY_NONE, result, details, duration_ms)


def _unavailable_from(result: http_client.HttpResult, url: str) -> Evidence:
    if result.rate_limited:
        return Evidence.unavailable(SOURCE, url, "rate limit exceeded (public API quota)", result.duration_ms)
    if result.status_code in (401, 403):
        return Evidence.unavailable(SOURCE, url, "API key rejected", result.duration_ms)
    return Evidence.unavailable(SOURCE, url, result.error or "unknown error", result.duration_ms)


def check_url(url: str, api_key: str | None = None, poll_timeout: float | None = None, sleep=time.sleep) -> Evidence:
    api_key = api_key if api_key is not None else config_settings.settings.virustotal_api_key
    poll_timeout = poll_timeout if poll_timeout is not None else config_settings.settings.virustotal_poll_timeout_seconds
    try:
        parsed = parse_url(url)
    except URLValidationError as exc:
        return Evidence.failed(SOURCE, url, f"invalid URL: {exc}")
    target = parsed.normalized
    if not api_key or api_key.startswith("your_"):
        return Evidence.not_configured(SOURCE, target)

    headers = _headers(api_key)
    started = time.monotonic()

    # 1. Existing report
    report = http_client.request("GET", f"{BASE}/urls/{url_id(target)}", headers=headers)
    if report.ok and isinstance(report.json, dict):
        attrs = (report.json.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        if stats:
            extra = {"reputation": attrs.get("reputation"), "last_analysis_date": attrs.get("last_analysis_date"), "categories": attrs.get("categories"), "source": "existing report"}
            return parse_stats(target, stats, extra, report.duration_ms)
    elif report.status_code not in (404,):
        return _unavailable_from(report, target)

    # 2. Submit for analysis
    submit = http_client.request("POST", f"{BASE}/urls", headers=headers, data={"url": target})
    if not submit.ok or not isinstance(submit.json, dict):
        return _unavailable_from(submit, target)
    analysis_id = (submit.json.get("data") or {}).get("id")
    if not analysis_id:
        return Evidence.unavailable(SOURCE, target, "no analysis id returned", submit.duration_ms)

    # 3. Poll (bounded)
    last_status = "queued"
    while time.monotonic() - started < poll_timeout:
        analysis = http_client.request("GET", f"{BASE}/analyses/{analysis_id}", headers=headers)
        if not analysis.ok or not isinstance(analysis.json, dict):
            return _unavailable_from(analysis, target)
        attrs = (analysis.json.get("data") or {}).get("attributes") or {}
        last_status = attrs.get("status", "queued")
        if last_status == "completed":
            duration = int((time.monotonic() - started) * 1000)
            return parse_stats(target, attrs.get("stats") or {}, {"source": "new analysis", "analysis_id": analysis_id}, duration)
        sleep(config_settings.settings.virustotal_poll_interval_seconds)
    duration = int((time.monotonic() - started) * 1000)
    return Evidence.unavailable(SOURCE, target, f"analysis still '{last_status}' after {poll_timeout:.0f}s; result not available yet", duration)
