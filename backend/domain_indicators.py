"""Static, offline examination of a URL's domain features.

Never connects to the target. Works purely on the parsed hostname/path.
"""
from __future__ import annotations

import re

from backend.evidence import Evidence
from config.constants import (
    BD_BRAND_KEYWORDS,
    OFFICIAL_DOMAINS,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_NONE,
    STATUS_COMPLETED,
    STATUS_NOT_FOUND,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from utils.security import URLValidationError, parse_url

SOURCE = "domain"
_SUSPICIOUS_PATH_RE = re.compile(r"(login|signin|verify|verification|otp|claim|reward|prize|secure|update|account|confirm|wallet|bonus|free|gift|unlock|password)", re.I)


def _brand_in(text: str) -> str | None:
    compact = text.replace("-", "").replace(".", "")
    for brand in BD_BRAND_KEYWORDS:
        if brand.replace(" ", "") in compact:
            return brand
    return None


def get_domain_indicators(url: str) -> Evidence:
    try:
        parsed = parse_url(url)
    except URLValidationError as exc:
        return Evidence.failed(SOURCE, url, f"invalid URL: {exc}")

    indicators: list[dict] = []

    def add(key: str, label: str, weight: int, detail: str = ""):
        indicators.append({"key": key, "label": label, "weight": weight, "detail": detail})

    host = parsed.host
    registered = parsed.registered_domain
    is_official = registered in OFFICIAL_DOMAINS

    if parsed.is_ip:
        add("ip_address_host", "Uses a raw IP address instead of a domain", 4, host)
    if parsed.is_punycode:
        add("punycode", "Internationalized (punycode) domain — possible lookalike characters", 4, host)
    if not is_official:
        brand = _brand_in(registered)
        if brand:
            add("brand_lookalike_domain", f"Domain contains the brand name '{brand}' but is not the official domain", 5, registered)
        else:
            sub_brand = _brand_in(parsed.subdomain)
            if sub_brand:
                add("brand_in_subdomain", f"Brand name '{sub_brand}' used as a subdomain of an unrelated domain", 5, host)
    if parsed.suffix and parsed.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"Top-level domain '.{parsed.suffix}' is frequently abused", 3, parsed.suffix)
    if not parsed.suffix and not parsed.is_ip:
        add("unrecognised_tld", "Top-level domain is not a recognised public suffix", 2, host)
    if registered in URL_SHORTENERS:
        add("url_shortener", "Link shortener hides the real destination", 3, registered)
    if parsed.subdomain and parsed.subdomain.count(".") >= 2:
        add("many_subdomains", "Unusually deep subdomain structure", 2, parsed.subdomain)
    if registered.count("-") >= 2:
        add("hyphenated_domain", "Multiple hyphens in domain name", 1, registered)
    if len(host) > 40:
        add("long_hostname", "Very long hostname", 1, str(len(host)))
    if re.search(r"\d", registered.split(".")[0]) and not parsed.is_ip:
        add("digits_in_domain", "Digits mixed into the domain name", 1, registered)
    if parsed.port not in (None, 80, 443):
        add("non_standard_port", f"Non-standard port {parsed.port}", 2, str(parsed.port))
    if parsed.scheme == "http":
        add("no_https", "Plain HTTP (no encryption)", 1, "http")
    if _SUSPICIOUS_PATH_RE.search(parsed.path) and not is_official:
        add("suspicious_path_keyword", "Path uses credential/reward keywords", 2, parsed.path[:60])

    weight = sum(i["weight"] for i in indicators)
    if weight >= 8:
        severity = SEVERITY_HIGH
    elif weight >= 4:
        severity = SEVERITY_MEDIUM
    elif weight >= 1:
        severity = SEVERITY_LOW
    else:
        severity = SEVERITY_NONE
    details = {
        "host": host,
        "registered_domain": registered,
        "subdomain": parsed.subdomain,
        "tld": parsed.suffix,
        "is_official_domain": is_official,
        "indicators": indicators,
        "raw_weight": weight,
    }
    if indicators:
        result = f"{len(indicators)} suspicious domain feature(s): " + "; ".join(i["label"] for i in indicators[:3]) + ("…" if len(indicators) > 3 else "")
        return Evidence.build(SOURCE, parsed.normalized, STATUS_COMPLETED, severity, result, details)
    result = "No suspicious domain features found." + (" Official domain." if is_official else "")
    return Evidence.build(SOURCE, parsed.normalized, STATUS_NOT_FOUND, SEVERITY_NONE, result, details)
