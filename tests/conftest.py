import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import json  # noqa: E402

import pytest  # noqa: E402

from integrations import http_client  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class FakeHttp:
    """Scripted replacement for integrations.http_client.request."""

    def __init__(self):
        self.responses = []
        self.calls = []

    def queue(self, ok=True, status=200, json=None, error=None):
        self.responses.append(http_client.HttpResult(ok, status, json, error, 5))
        return self

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError(f"Unexpected HTTP call: {method} {url}")
        return self.responses.pop(0)


@pytest.fixture
def fake_http(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(http_client, "request", fake)
    return fake


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    from database import db

    url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setattr(db, "_engine", None)
    monkeypatch.setattr(db, "_SessionLocal", None)
    db.init_db(url)
    yield url
