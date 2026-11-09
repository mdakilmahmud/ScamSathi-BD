"""Thin requests wrapper with explicit timeouts and a single bounded retry.

Only used for talking to security-intelligence APIs. It must never be used
to fetch a user-submitted URL.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests

from config import settings as config_settings

RETRYABLE_STATUS = {500, 502, 503, 504}
MAX_ATTEMPTS = 2

_session = requests.Session()
_session.headers.update({"User-Agent": "ScamSathiBD/1.0 (+security-research)"})


@dataclass
class HttpResult:
    ok: bool
    status_code: int | None
    json: Any
    error: str | None
    duration_ms: int

    @property
    def rate_limited(self) -> bool:
        return self.status_code == 429


def request(method: str, url: str, *, headers: dict | None = None, params: dict | None = None, json: Any = None, data: Any = None, timeout: float | None = None) -> HttpResult:
    timeout = timeout or config_settings.settings.http_timeout_seconds
    started = time.monotonic()
    last_error: str | None = None
    status: int | None = None
    body: Any = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = _session.request(method, url, headers=headers, params=params, json=json, data=data, timeout=timeout, allow_redirects=False)
            status = resp.status_code
            try:
                body = resp.json() if resp.content else None
            except ValueError:
                body = None
            if status in RETRYABLE_STATUS and attempt < MAX_ATTEMPTS:
                time.sleep(0.5)
                continue
            ok = 200 <= status < 300
            error = None if ok else f"HTTP {status}"
            return HttpResult(ok, status, body, error, int((time.monotonic() - started) * 1000))
        except requests.Timeout:
            last_error = f"timeout after {timeout:.0f}s"
        except requests.ConnectionError:
            last_error = "connection error"
        except requests.RequestException as exc:  # pragma: no cover - defensive
            last_error = f"request error: {exc.__class__.__name__}"
        if attempt < MAX_ATTEMPTS:
            time.sleep(0.5)
    return HttpResult(False, status, body, last_error or "request failed", int((time.monotonic() - started) * 1000))
