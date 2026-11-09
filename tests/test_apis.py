from integrations import safe_browsing, urlhaus, virustotal
from tests.conftest import load_fixture


def test_safe_browsing_request_body_shape():
    body = safe_browsing.build_request_body("https://x.test/")
    assert body["client"]["clientId"] == "scamsathibd"
    assert "SOCIAL_ENGINEERING" in body["threatInfo"]["threatTypes"]
    assert body["threatInfo"]["threatEntries"] == [{"url": "https://x.test/"}]


def test_safe_browsing_match(fake_http):
    fake_http.queue(json=load_fixture("safe_browsing_match.json"))
    ev = safe_browsing.check_url("http://testsafebrowsing.appspot.com/s/phishing.html", api_key="k")
    assert ev.status == "completed" and ev.severity == "high" and ev.is_positive
    assert fake_http.calls[0][2]["params"] == {"key": "k"}


def test_safe_browsing_no_match_is_not_found(fake_http):
    fake_http.queue(json={})
    ev = safe_browsing.check_url("https://www.wikipedia.org/", api_key="k")
    assert ev.status == "not_found" and not ev.is_positive and "not proof" in ev.result


def test_safe_browsing_not_configured_and_errors(fake_http):
    assert safe_browsing.check_url("https://x.test/", api_key="").status == "not_configured"
    fake_http.queue(ok=False, status=429, error="HTTP 429")
    assert "rate limit" in safe_browsing.check_url("https://x.test/", api_key="k").result
    fake_http.queue(ok=False, status=None, error="timeout after 10s")
    ev = safe_browsing.check_url("https://x.test/", api_key="k")
    assert ev.status == "unavailable" and "timeout" in ev.result
    assert safe_browsing.check_url("http://127.0.0.1/", api_key="k").status == "failed"


def test_virustotal_existing_report(fake_http):
    fake_http.queue(json=load_fixture("virustotal_report.json"))
    ev = virustotal.check_url("https://x.test/", api_key="k")
    assert ev.status == "completed" and ev.details["stats"]["malicious"] == 2 and ev.severity == "medium"
    assert fake_http.calls[0][1].endswith("/urls/" + virustotal.url_id("https://x.test/"))


def test_virustotal_submit_and_poll(fake_http):
    fake_http.queue(ok=False, status=404, error="HTTP 404")
    fake_http.queue(json={"data": {"id": "analysis-fixture"}})
    fake_http.queue(json={"data": {"attributes": {"status": "queued"}}})
    fake_http.queue(json=load_fixture("virustotal_analysis_completed.json"))
    ev = virustotal.check_url("https://x.test/", api_key="k", poll_timeout=30, sleep=lambda s: None)
    assert ev.status == "completed" and ev.severity == "high" and ev.details["stats"]["malicious"] == 6
    assert len(fake_http.calls) == 4


def test_virustotal_poll_timeout_is_unavailable(fake_http):
    fake_http.queue(ok=False, status=404, error="HTTP 404")
    fake_http.queue(json={"data": {"id": "analysis-fixture"}})
    ev = virustotal.check_url("https://x.test/", api_key="k", poll_timeout=0, sleep=lambda s: None)
    assert ev.status == "unavailable" and "queued" in ev.result


def test_virustotal_rate_limit(fake_http):
    fake_http.queue(ok=False, status=429, error="HTTP 429")
    ev = virustotal.check_url("https://x.test/", api_key="k")
    assert ev.status == "unavailable" and "quota" in ev.result


def test_urlhaus_hit_and_miss(fake_http):
    fake_http.queue(json=load_fixture("urlhaus_hit.json"))
    ev = urlhaus.check_url("http://example-malware.test/payload.exe", auth_key="k")
    assert ev.status == "completed" and ev.severity == "high" and ev.details["threat"] == "malware_download"
    assert fake_http.calls[0][2]["headers"] == {"Auth-Key": "k"}
    fake_http.queue(json={"query_status": "no_results"})
    assert urlhaus.check_url("https://x.test/", auth_key="k").status == "not_found"
    assert urlhaus.check_url("https://x.test/", auth_key="").status == "not_configured"
    fake_http.queue(ok=False, status=401, error="HTTP 401")
    assert urlhaus.check_url("https://x.test/", auth_key="k").status == "unavailable"
