import pytest

from backend.classifier import classify_input
from utils.security import URLValidationError, minimize_for_storage, parse_url, redact_sensitive
from utils.url_extractor import extract_urls
from utils.validators import InvalidInputError, validate_submission


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "data:text/html,hi", "http://localhost/", "http://127.0.0.1/", "http://10.0.0.5/x", "http://192.168.1.1", "http://[::1]/", "http://user:pw@example.com/", "ftp://example.com/", "http://", "not a url"])
def test_rejects_unsafe_urls(url):
    with pytest.raises(URLValidationError):
        parse_url(url)


def test_parses_and_normalizes_public_url():
    parsed = parse_url("HTTPS://BKash-Offer.XYZ/claim?x=1")
    assert parsed.host == "bkash-offer.xyz"
    assert parsed.registered_domain == "bkash-offer.xyz"
    assert parsed.suffix == "xyz"
    assert parsed.normalized == "https://bkash-offer.xyz/claim?x=1"


def test_idn_hostname_becomes_punycode():
    parsed = parse_url("https://bкash.com/")  # Cyrillic к
    assert parsed.is_punycode
    assert parsed.host.startswith("xn--")


def test_reserved_test_tld_allowed():
    assert parse_url("https://example-suspicious-site.test/").host == "example-suspicious-site.test"


def test_extract_urls_filters_and_caps():
    text = "see https://a.example.com/x and www.b.example.com, also http://127.0.0.1/evil and bkash-offer.xyz/claim. https://c.example.com https://d.example.com"
    out = extract_urls(text, limit=3)
    assert out["truncated"] is True
    assert len(out["urls"]) == 3
    assert "http://127.0.0.1/evil" in out["rejected"]
    assert all(u.startswith("http") for u in out["urls"])


def test_extract_urls_ignores_bangla_text_without_links():
    out = extract_urls("অভিনন্দন! আপনি ৫০,০০০ টাকা জিতেছেন।")
    assert out["urls"] == []


def test_validate_submission_limits():
    with pytest.raises(InvalidInputError):
        validate_submission("   ")
    with pytest.raises(InvalidInputError):
        validate_submission("x" * 6000)
    with pytest.raises(InvalidInputError):
        validate_submission("hello", mode="weird")
    sub = validate_submission("  hello\x00 ", language="bn")
    assert sub.content == "hello" and sub.language == "bn"


def test_classifier_types():
    assert classify_input("https://www.wikipedia.org/").input_type == "URL"
    assert classify_input("Congrats, claim at https://x.example.com/win").input_type == "Mixed"
    assert classify_input("Dear customer, your account is blocked").input_type == "Message"
    email = "From: support@bank.example\nSubject: Verify\n\nDear user, click https://x.example.com"
    assert classify_input(email).input_type == "Email"
    with pytest.raises(URLValidationError):
        classify_input("javascript:alert(1)")
    with pytest.raises(URLValidationError):
        classify_input("not-a-url", mode="url")


def test_redaction_masks_digit_runs():
    assert redact_sensitive("OTP 482913 and pin 1234") == "OTP 48**** and pin 12**"
    assert len(minimize_for_storage("a" * 1000)) <= 501
