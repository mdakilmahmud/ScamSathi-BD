"""Tool registry: declarations shown to the model plus validated Python executors.

Every argument is validated with Pydantic before execution. URL arguments must
be one of the URLs the classifier extracted from the user's submission, so the
model can never invent or redirect a lookup target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from pydantic import BaseModel, Field, ValidationError

from backend.domain_indicators import get_domain_indicators
from backend.evidence import Evidence
from backend.message_analysis import analysis_to_evidence, analyze_message
from config.constants import MAX_INPUT_LENGTH
from config import settings as config_settings
from integrations import safe_browsing, urlhaus, virustotal
from utils.security import URLValidationError, parse_url
from utils.url_extractor import extract_urls


class ToolArgumentError(ValueError):
    pass


class UrlArgs(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


class MessageArgs(BaseModel):
    text: str = Field(default="", max_length=MAX_INPUT_LENGTH)


class NoArgs(BaseModel):
    pass


@dataclass
class ToolContext:
    content: str
    urls: list[str]
    has_message_text: bool
    language: str = "en"
    llm_analyzer: Callable[[str], dict] | None = None
    extra_message_findings: dict = field(default_factory=dict)


def resolve_url(ctx: ToolContext, url: str) -> str:
    try:
        normalized = parse_url(url).normalized
    except URLValidationError as exc:
        raise ToolArgumentError(f"Invalid URL argument: {exc}") from exc
    allowed = {u: u for u in ctx.urls}
    for u in ctx.urls:
        try:
            allowed[parse_url(u).host] = u
        except URLValidationError:
            continue
    if normalized in allowed:
        return allowed[normalized]
    host = parse_url(normalized).host
    if host in allowed:
        return allowed[host]
    raise ToolArgumentError("URL is not one of the URLs extracted from the submitted content.")


def tool_analyze_message(ctx: ToolContext, args: MessageArgs) -> Evidence:
    # Always analyse the actual submitted content, never model-rewritten text.
    analysis = analyze_message(ctx.content, contains_url=bool(ctx.urls))
    evidence = analysis_to_evidence(analysis)
    if ctx.llm_analyzer is not None:
        try:
            ai = ctx.llm_analyzer(ctx.content)
            if ai:
                evidence.details["ai_analysis"] = ai
                ctx.extra_message_findings = ai
        except Exception as exc:  # LLM interpretation is optional; never fail the tool
            evidence.details["ai_analysis_error"] = f"{exc.__class__.__name__}"
    return evidence


def tool_extract_urls(ctx: ToolContext, args: NoArgs) -> dict:
    extraction = extract_urls(ctx.content)
    return {"urls": ctx.urls or extraction["urls"], "rejected": extraction["rejected"], "truncated": extraction["truncated"]}


def tool_get_domain_indicators(ctx: ToolContext, args: UrlArgs) -> Evidence:
    return get_domain_indicators(resolve_url(ctx, args.url))


def tool_check_safe_browsing(ctx: ToolContext, args: UrlArgs) -> Evidence:
    return safe_browsing.check_url(resolve_url(ctx, args.url))


def tool_check_virustotal(ctx: ToolContext, args: UrlArgs) -> Evidence:
    return virustotal.check_url(resolve_url(ctx, args.url))


def tool_check_urlhaus(ctx: ToolContext, args: UrlArgs) -> Evidence:
    return urlhaus.check_url(resolve_url(ctx, args.url))


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    executor: Callable
    needs_url: bool
    source_key: str | None
    step_label: str

    def declaration(self) -> dict:
        if self.args_model is UrlArgs:
            params = {"type": "OBJECT", "properties": {"url": {"type": "STRING", "description": "One of the URLs extracted from the submission."}}, "required": ["url"]}
        elif self.args_model is MessageArgs:
            params = {"type": "OBJECT", "properties": {"text": {"type": "STRING", "description": "Optional. Ignored: the tool always analyses the original submission."}}}
        else:
            params = {"type": "OBJECT", "properties": {}}
        return {"name": self.name, "description": self.description, "parameters": params}


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in [
        ToolSpec("analyze_message", "Detect suspicious language and claims (urgency, prize, OTP/PIN requests, impersonation, payment pressure, job fraud) in the submitted text. Works for Bangla and English.", MessageArgs, tool_analyze_message, False, "message", "Analyzing message text"),
        ToolSpec("extract_urls", "List the validated URLs extracted from the submission, plus any rejected candidates.", NoArgs, tool_extract_urls, False, None, "Extracting URLs"),
        ToolSpec("get_domain_indicators", "Examine static domain features of a URL offline (lookalike brand names, abused TLDs, IP hosts, punycode, shorteners). Does not contact the site.", UrlArgs, tool_get_domain_indicators, True, "domain", "Examining domain features"),
        ToolSpec("check_safe_browsing", "Query Google Safe Browsing for known phishing/malware listings of a URL.", UrlArgs, tool_check_safe_browsing, True, "safe_browsing", "Querying Google Safe Browsing"),
        ToolSpec("check_virustotal", "Query VirusTotal for multi-engine reputation of a URL.", UrlArgs, tool_check_virustotal, True, "virustotal", "Querying VirusTotal"),
        ToolSpec("check_urlhaus", "Query URLhaus for malware-distribution reports about a URL. Not a phishing database.", UrlArgs, tool_check_urlhaus, True, "urlhaus", "Querying URLhaus"),
    ]
}


def available_tools(has_url: bool) -> list[ToolSpec]:
    specs = []
    for spec in TOOLS.values():
        if spec.needs_url and not has_url:
            continue
        specs.append(spec)
    return specs


def tool_configured(spec: ToolSpec) -> bool:
    return {
        "safe_browsing": config_settings.settings.safe_browsing_configured,
        "virustotal": config_settings.settings.virustotal_configured,
        "urlhaus": config_settings.settings.urlhaus_configured,
    }.get(spec.source_key or "", True)


def declarations(has_url: bool) -> list[dict]:
    return [spec.declaration() for spec in available_tools(has_url)]


def validate_args(spec: ToolSpec, raw_args: dict) -> BaseModel:
    try:
        return spec.args_model.model_validate(raw_args or {})
    except ValidationError as exc:
        raise ToolArgumentError(f"Invalid arguments for {spec.name}: {exc.errors()[0].get('msg', 'validation error')}") from exc
