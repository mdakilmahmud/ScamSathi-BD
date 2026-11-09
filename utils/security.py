"""URL safety checks. The backend never fetches user-submitted URLs; these
checks make sure we only hand well-formed public http(s) URLs to third-party
intelligence APIs and tool arguments."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import tldextract

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "broadcasthost"}
_HOST_RE = re.compile(r"^[a-z0-9.-]+$")

# Offline extraction: never let tldextract fetch the public suffix list at runtime.
_extractor = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


@dataclass(frozen=True)
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    host: str
    registered_domain: str
    subdomain: str
    suffix: str
    port: int | None
    path: str
    is_ip: bool
    is_punycode: bool


class URLValidationError(ValueError):
    """Raised when a URL must not be processed."""


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_host(host: str) -> str:
    host = unicodedata.normalize("NFKC", host).strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLValidationError("Hostname cannot be encoded safely.") from exc


def parse_url(raw: str) -> ParsedURL:
    """Validate and normalize a URL, rejecting anything we must not forward."""
    if not isinstance(raw, str):
        raise URLValidationError("URL must be text.")
    candidate = raw.strip()
    if not candidate:
        raise URLValidationError("URL is empty.")
    if len(candidate) > 2048:
        raise URLValidationError("URL is too long.")
    if any(ch.isspace() for ch in candidate):
        raise URLValidationError("URL contains whitespace.")
    if "://" not in candidate:
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", candidate)
        if scheme_match and scheme_match.group(1).lower() not in ALLOWED_SCHEMES:
            raise URLValidationError(
                f"Unsupported URL scheme '{scheme_match.group(1).lower()}'. Only http and https are allowed."
            )
        candidate = "http://" + candidate

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Unsupported URL scheme '{scheme}'. Only http and https are allowed.")
    if not parts.hostname:
        raise URLValidationError("URL has no hostname.")
    if parts.username or parts.password:
        raise URLValidationError("URLs with embedded credentials are not supported.")

    host = normalize_host(parts.hostname)
    if host in BLOCKED_HOSTNAMES or host.endswith(".localhost") or host.endswith(".local"):
        raise URLValidationError("Local hostnames are not allowed.")
    is_ip = _looks_like_ip(host)
    if is_ip and _is_private_ip(host):
        raise URLValidationError("Private or loopback network addresses are not allowed.")
    if not is_ip and not _HOST_RE.match(host):
        raise URLValidationError("Hostname contains invalid characters.")
    if not is_ip and "." not in host:
        raise URLValidationError("Hostname must contain a domain.")

    try:
        port = parts.port
    except ValueError as exc:
        raise URLValidationError("Invalid port.") from exc

    ext = _extractor(host)
    registered = ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain
    if not is_ip and not ext.suffix:
        # Unknown / reserved TLD (e.g. .test, .example): keep the whole host as the
        # registered domain and let the domain-indicator tool flag it.
        registered = host

    netloc = host if port is None else f"{host}:{port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ParsedURL(
        original=raw.strip(),
        normalized=normalized,
        scheme=scheme,
        host=host,
        registered_domain=registered or host,
        subdomain=ext.subdomain,
        suffix=ext.suffix,
        port=port,
        path=parts.path or "/",
        is_ip=is_ip,
        is_punycode="xn--" in host,
    )


def is_safe_public_url(raw: str) -> bool:
    try:
        parse_url(raw)
        return True
    except URLValidationError:
        return False


def redact_sensitive(text: str) -> str:
    """Mask long digit runs (OTPs, PINs, card/phone numbers) before storage."""
    return re.sub(r"(?<!\d)\d{4,}(?!\d)", lambda m: m.group(0)[:2] + "*" * (len(m.group(0)) - 2), text)


def minimize_for_storage(text: str, limit: int = 500) -> str:
    text = redact_sensitive(text.strip())
    return text if len(text) <= limit else text[:limit] + "…"
