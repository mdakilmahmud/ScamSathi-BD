"""Deterministic, documented risk scoring. The LLM never touches this.

Score = sum of capped per-group contributions (see config.constants.WEIGHTS).
Confidence describes investigation completeness, independent of the score.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from backend.evidence import Evidence
from config.constants import (
    INVESTIGATION_COMPLETE,
    INVESTIGATION_FAILED,
    INVESTIGATION_PARTIAL,
    RISK_LEVELS,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    STATUS_NOT_CONFIGURED,
    STATUS_SKIPPED,
    WEIGHTS,
)

EXTERNAL_SOURCES = ("safe_browsing", "virustotal", "urlhaus")
MESSAGE_FLOOR_MULTIPLIER = 10
MESSAGE_FLOOR_CAP = 80
DOMAIN_FLOOR_MULTIPLIER = 4
DOMAIN_FLOOR_CAP = 45
# A URL explicitly listed as phishing/malware by a security provider is a confirmed
# threat; its score never falls below the High threshold.
CONFIRMED_THREAT_FLOOR = 70
EXTERNAL_GROUPS = ("safe_browsing", "virustotal", "urlhaus")


class Contribution(BaseModel):
    group: str
    points: int
    maximum: int
    basis: str


class RiskResult(BaseModel):
    score: int
    level: str
    confidence: str
    investigation_status: str
    contributions: list[Contribution]
    notes: list[str] = Field(default_factory=list)
    sources_completed: list[str] = Field(default_factory=list)
    sources_unavailable: list[str] = Field(default_factory=list)
    sources_not_configured: list[str] = Field(default_factory=list)
    sources_skipped: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return self.model_dump()


def level_for_score(score: int) -> str:
    for low, high, label in RISK_LEVELS:
        if low <= score < high:
            return label
    return RISK_LEVELS[-1][2]


def _safe_browsing_points(items: list[Evidence]) -> tuple[int, str]:
    best = 0
    basis = "no match in requested lists" if any(e.ran for e in items) else "not checked"
    for e in items:
        if not e.is_positive:
            continue
        points = WEIGHTS["safe_browsing"] if e.severity == SEVERITY_HIGH else 25
        if points > best:
            best, basis = points, f"listed as {', '.join(e.details.get('threat_types', []))}"
    return best, basis


def _virustotal_points(items: list[Evidence]) -> tuple[int, str]:
    best = 0
    basis = "no engine detections" if any(e.ran for e in items) else "not checked"
    for e in items:
        if not e.ran:
            continue
        stats = e.details.get("stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious >= 5:
            points = 25
        elif malicious >= 2:
            points = 18
        elif malicious == 1:
            points = 10
        else:
            points = 0
        points += 4 if suspicious >= 2 else (2 if suspicious == 1 else 0)
        points = min(points, WEIGHTS["virustotal"])
        if points > best:
            best, basis = points, f"{malicious} malicious / {suspicious} suspicious engine verdicts"
    return best, basis


def _urlhaus_points(items: list[Evidence]) -> tuple[int, str]:
    best = 0
    basis = "not found in dataset" if any(e.ran for e in items) else "not checked"
    for e in items:
        if not e.is_positive:
            continue
        points = WEIGHTS["urlhaus"] if e.severity == SEVERITY_HIGH else 12
        if points > best:
            best, basis = points, f"reported as {e.details.get('threat', 'malware')} ({e.details.get('url_status', 'unknown')})"
    return best, basis


def _weighted_points(items: list[Evidence], group: str, empty_basis: str) -> tuple[int, str]:
    best, basis = 0, empty_basis if any(e.ran for e in items) else "not analysed"
    for e in items:
        if not e.ran:
            continue
        weight = int(e.details.get("raw_weight", 0) or 0)
        points = min(weight, WEIGHTS[group])
        if points > best or (points == best and basis == empty_basis):
            labels = [i["label"] for i in e.details.get("indicators", [])]
            best, basis = points, (", ".join(labels[:4]) if labels else empty_basis)
    return best, basis


def calculate_risk(evidence: list[Evidence], has_url: bool = True, llm_available: bool = True) -> RiskResult:
    by_group: dict[str, list[Evidence]] = {}
    for e in evidence:
        by_group.setdefault(e.source_key, []).append(e)

    contributions: list[Contribution] = []
    sb, sb_basis = _safe_browsing_points(by_group.get("safe_browsing", []))
    contributions.append(Contribution(group="safe_browsing", points=sb, maximum=WEIGHTS["safe_browsing"], basis=sb_basis))
    vt, vt_basis = _virustotal_points(by_group.get("virustotal", []))
    contributions.append(Contribution(group="virustotal", points=vt, maximum=WEIGHTS["virustotal"], basis=vt_basis))
    uh, uh_basis = _urlhaus_points(by_group.get("urlhaus", []))
    contributions.append(Contribution(group="urlhaus", points=uh, maximum=WEIGHTS["urlhaus"], basis=uh_basis))
    dom, dom_basis = _weighted_points(by_group.get("domain", []), "domain", "no suspicious domain features")
    contributions.append(Contribution(group="domain", points=dom, maximum=WEIGHTS["domain"], basis=dom_basis))
    msg, msg_basis = _weighted_points(by_group.get("message", []), "message", "no scam language indicators")
    contributions.append(Contribution(group="message", points=msg, maximum=WEIGHTS["message"], basis=msg_basis))

    score = max(0, min(100, sum(c.points for c in contributions)))

    # Message-indicator floor: an OTP/PIN request or advance-fee demand is dangerous
    # regardless of URL reputation, so strong text indicators set a documented floor
    # (raw weight x MESSAGE_FLOOR_MULTIPLIER, capped). Only API evidence can push above it.
    # Likewise a brand-lookalike domain is a strong phishing signal on its own, so
    # domain features set a smaller documented floor.
    floor_notes: list[str] = []
    message_weight = max((int(e.details.get("raw_weight", 0) or 0) for e in by_group.get("message", []) if e.ran), default=0)
    domain_weight = max((int(e.details.get("raw_weight", 0) or 0) for e in by_group.get("domain", []) if e.ran), default=0)
    message_floor = min(MESSAGE_FLOOR_CAP, message_weight * MESSAGE_FLOOR_MULTIPLIER)
    domain_floor = min(DOMAIN_FLOOR_CAP, domain_weight * DOMAIN_FLOOR_MULTIPLIER)
    if message_floor > score and message_floor >= domain_floor:
        floor_notes.append(f"Score raised to {message_floor} by the message-indicator floor (indicator weight {message_weight} x {MESSAGE_FLOOR_MULTIPLIER}, cap {MESSAGE_FLOOR_CAP}).")
        score = message_floor
    elif domain_floor > score:
        floor_notes.append(f"Score raised to {domain_floor} by the domain-indicator floor (indicator weight {domain_weight} x {DOMAIN_FLOOR_MULTIPLIER}, cap {DOMAIN_FLOOR_CAP}).")
        score = domain_floor
    confirmed = [e.source for g in EXTERNAL_GROUPS for e in by_group.get(g, []) if e.ran and e.severity == SEVERITY_HIGH]
    if confirmed and score < CONFIRMED_THREAT_FLOOR:
        floor_notes.append(f"Score raised to {CONFIRMED_THREAT_FLOOR}: {', '.join(dict.fromkeys(confirmed))} explicitly list this URL as a threat.")
        score = CONFIRMED_THREAT_FLOOR
    level = level_for_score(score)

    # Completeness / confidence
    completed, unavailable, not_configured, skipped = [], [], [], []
    for source in EXTERNAL_SOURCES:
        items = by_group.get(source, [])
        if not items:
            if has_url:
                skipped.append(source)
            continue
        if any(e.ran for e in items):
            completed.append(source)
        elif all(e.status == STATUS_NOT_CONFIGURED for e in items):
            not_configured.append(source)
        elif all(e.status == STATUS_SKIPPED for e in items):
            skipped.append(source)
        else:
            unavailable.append(source)

    notes: list[str] = list(floor_notes)
    if has_url:
        applicable = [s for s in EXTERNAL_SOURCES if s not in not_configured]
        ran = [s for s in applicable if s in completed]
        if not applicable:
            confidence = "Low"
            notes.append("No external security API is configured; score relies on offline analysis only.")
        elif len(ran) == len(applicable):
            confidence = "High"
        elif ran:
            confidence = "Medium"
        else:
            confidence = "Low"
        if unavailable:
            notes.append("Unavailable sources contribute no evidence for or against safety: " + ", ".join(unavailable) + ".")
        if skipped:
            notes.append("Not checked this run: " + ", ".join(skipped) + ".")
        if not_configured:
            notes.append("Not configured: " + ", ".join(not_configured) + ".")
        if unavailable or skipped:
            status = INVESTIGATION_PARTIAL
        elif not completed and not applicable:
            status = INVESTIGATION_PARTIAL
        else:
            status = INVESTIGATION_COMPLETE
        if not completed and not by_group.get("domain") and not by_group.get("message"):
            status = INVESTIGATION_FAILED
            confidence = "Low"
    else:
        analysed = any(e.ran for e in by_group.get("message", []))
        if not analysed:
            confidence, status = "Low", INVESTIGATION_FAILED
        else:
            confidence = "High" if llm_available else "Medium"
            status = INVESTIGATION_COMPLETE
            if not llm_available:
                notes.append("AI message interpretation unavailable; rule-based indicators only.")

    if score < 20 and not any(e.is_positive for e in evidence):
        notes.append("A low score means no significant indicators were found in the evidence collected — it is not a guarantee of safety.")

    return RiskResult(
        score=score,
        level=level,
        confidence=confidence,
        investigation_status=status,
        contributions=contributions,
        notes=notes,
        sources_completed=completed,
        sources_unavailable=unavailable,
        sources_not_configured=not_configured,
        sources_skipped=skipped,
    )
