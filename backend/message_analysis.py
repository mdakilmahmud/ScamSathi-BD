"""Deterministic, bilingual scam-indicator detection for message text.

These are warning signs, not proof of fraud. Only indicators detected here
contribute to the risk score; LLM-identified indicators are shown separately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from backend.evidence import Evidence
from config.constants import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_NONE, STATUS_COMPLETED, STATUS_NOT_FOUND

SOURCE = "message"


@dataclass(frozen=True)
class IndicatorRule:
    key: str
    label_en: str
    label_bn: str
    weight: int
    pattern: re.Pattern


def _rule(key, label_en, label_bn, weight, pattern) -> IndicatorRule:
    return IndicatorRule(key, label_en, label_bn, weight, re.compile(pattern, re.IGNORECASE | re.UNICODE))


RULES: list[IndicatorRule] = [
    _rule("otp_request", "OTP / verification code request", "OTP / ভেরিফিকেশন কোড চাওয়া", 3,
          r"\b(otp|one[- ]?time[- ]?(pass(word|code)?|pin)|verification code|security code)\b|ওটিপি|ভেরিফিকেশন কোড|যাচাই(করণ)? কোড"),
    _rule("pin_request", "PIN / password request", "PIN / পাসওয়ার্ড চাওয়া", 3,
          r"\b(pin|password|passcode|cvv|card number|atm pin)\b|পিন|পাসওয়ার্ড|কার্ড নম্বর|গোপন নম্বর"),
    _rule("prize_claim", "Prize / lottery claim", "পুরস্কার / লটারি জেতার দাবি", 2,
          r"\b(congratulations?|you (have )?won|winner|prize|lottery|lucky draw|reward|gift|jackpot|cash ?back|claim your)\b|অভিনন্দন|জিতেছেন|পুরস্কার|লটারি|উপহার|বিজয়ী"),
    _rule("urgency", "Urgent call to action", "জরুরি পদক্ষেপের চাপ", 1,
          r"\b(immediately|urgent(ly)?|right now|act now|claim .{0,30}now|today only|within (24|12|48) hours|expires?( soon| today)?|last chance|hurry|limited time|final (notice|warning))\b|এখনই|অবিলম্বে|জরুরি|আজই|শেষ সুযোগ|দ্রুত|সময় শেষ"),
    _rule("account_threat", "Account block / suspension threat", "অ্যাকাউন্ট বন্ধের হুমকি", 2,
          r"\b(account|wallet|number|sim)\b.{0,40}\b(block(ed)?|suspend(ed)?|lock(ed)?|clos(ed|ure)|deactivat(ed|ion)|terminat(ed|ion)|disabled?)\b|\b(block(ed)?|suspend(ed)?|lock(ed)?)\b.{0,30}\baccount\b|অ্যাকাউন্ট.{0,30}(বন্ধ|লক|স্থগিত|বাতিল)|(বন্ধ|লক|স্থগিত).{0,30}অ্যাকাউন্ট"),
    _rule("impersonation", "Impersonation of a trusted organisation", "বিশ্বস্ত প্রতিষ্ঠানের ছদ্মবেশ", 2,
          r"\b(bkash|nagad|rocket|upay|bank|customer (care|service)|help ?line|official|government|police|ministry|bangladesh bank|nid|election commission|grameenphone|robi|banglalink|daraz|facebook|microsoft|google|paypal|amazon)\b|বিকাশ|নগদ|রকেট|ব্যাংক|কাস্টমার কেয়ার|হেল্পলাইন|সরকারি|পুলিশ|অফিসিয়াল"),
    _rule("payment_pressure", "Advance payment / fee request", "অগ্রিম টাকা / ফি চাওয়া", 2,
          r"\b(pay(ment)? (a |the )?(small |processing |delivery |registration |security |release )?(fee|charge|deposit|amount)|send (money|tk|taka|bdt|cash)|advance (payment|fee)|processing fee|registration fee|delivery charge|cash ?out|send money|bikash|recharge)\b|টাকা পাঠান|ফি (দিন|প্রদান|পরিশোধ)|অগ্রিম|সেন্ড মানি|ক্যাশ আউট|রেজিস্ট্রেশন ফি|প্রসেসিং ফি|ডেলিভারি চার্জ"),
    _rule("job_fraud", "Job offer with payment or unrealistic pay", "চাকরির প্রলোভন / নিয়োগ প্রতারণা", 2,
          r"\b(job|hiring|vacancy|recruit(ment|ing)?|salary|work from home|part[- ]time|earn (tk|taka|money|daily|\d)|daily income|interview fee|training fee)\b|চাকরি|নিয়োগ|বেতন|ঘরে বসে (আয়|ইনকাম)|পার্ট ?টাইম|দৈনিক আয়"),
    _rule("personal_data_request", "Request for personal identity data", "ব্যক্তিগত পরিচয় তথ্য চাওয়া", 2,
          r"\b(nid|national id|date of birth|mother'?s name|passport (number|no)|account number|card details)\b|জাতীয় পরিচয়পত্র|এনআইডি|জন্ম ?তারিখ|মায়ের নাম|অ্যাকাউন্ট নম্বর"),
    _rule("too_good_to_be_true", "Unrealistic guarantee or return", "অবাস্তব লাভের প্রতিশ্রুতি", 1,
          r"\b(100 ?% (guaranteed|safe|profit)|guaranteed (profit|income|return)|double your|triple your|risk[- ]free|free money)\b|নিশ্চিত (লাভ|আয়|মুনাফা)|দ্বিগুণ|ঝুঁকিমুক্ত|বিনামূল্যে টাকা"),
    _rule("prompt_injection", "Prompt-injection attempt in text", "প্রম্পট ইনজেকশনের চেষ্টা", 1,
          r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)|disregard (all |your )?(previous |prior )?instructions|reveal (your|the) (system )?prompt|you are now (a|an|the)\b|system prompt|developer message|act as (a|an) (unrestricted|different)|mark (this|it) (as )?safe|rate (this|it) (as )?(safe|low)"),
]

MESSAGE_TYPES = [
    ("Potential OTP / credential phishing", "সম্ভাব্য OTP / তথ্য ফিশিং", {"otp_request", "pin_request"}),
    ("Potential prize / lottery scam", "সম্ভাব্য পুরস্কার / লটারি প্রতারণা", {"prize_claim"}),
    ("Potential job / recruitment scam", "সম্ভাব্য চাকরি প্রতারণা", {"job_fraud"}),
    ("Potential account-suspension phishing", "সম্ভাব্য অ্যাকাউন্ট বন্ধের ফিশিং", {"account_threat"}),
    ("Potential advance-fee scam", "সম্ভাব্য অগ্রিম-ফি প্রতারণা", {"payment_pressure"}),
    ("Potential impersonation", "সম্ভাব্য ছদ্মবেশ", {"impersonation"}),
]


@dataclass
class MessageAnalysis:
    message_type: str
    message_type_bn: str
    indicators: list[dict] = field(default_factory=list)
    contains_url: bool = False
    contains_bangla: bool = False
    raw_weight: int = 0
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "message_type": self.message_type,
            "message_type_bn": self.message_type_bn,
            "suspicious_indicators": [i["label"] for i in self.indicators],
            "indicators": self.indicators,
            "contains_url": self.contains_url,
            "contains_bangla": self.contains_bangla,
            "raw_weight": self.raw_weight,
            "explanation": self.explanation,
        }


def analyze_message(text: str, contains_url: bool = False) -> MessageAnalysis:
    found: list[dict] = []
    for rule in RULES:
        match = rule.pattern.search(text)
        if match:
            snippet = text[max(0, match.start() - 20): match.end() + 20].replace("\n", " ")
            found.append({"key": rule.key, "label": rule.label_en, "label_bn": rule.label_bn, "weight": rule.weight, "snippet": snippet.strip()})
    keys = {f["key"] for f in found}
    message_type, message_type_bn = "No specific scam pattern detected", "নির্দিষ্ট কোনো প্রতারণার ধরন শনাক্ত হয়নি"
    for label_en, label_bn, trigger in MESSAGE_TYPES:
        if keys & trigger:
            message_type, message_type_bn = label_en, label_bn
            break
    if {"prize_claim", "payment_pressure"} <= keys:
        message_type, message_type_bn = "Potential advance-fee prize scam", "সম্ভাব্য অগ্রিম-ফি পুরস্কার প্রতারণা"
    if {"job_fraud", "payment_pressure"} <= keys:
        message_type, message_type_bn = "Potential job scam requesting payment", "টাকা চাওয়া চাকরি প্রতারণা"
    raw_weight = sum(f["weight"] for f in found)
    contains_bangla = any("\u0980" <= ch <= "\u09FF" for ch in text)
    if found:
        explanation = "Detected: " + ", ".join(f["label"] for f in found) + ". These are warning signs, not proof of fraud."
    else:
        explanation = "No common scam language patterns were detected. Absence of patterns does not guarantee the message is genuine."
    return MessageAnalysis(message_type, message_type_bn, found, contains_url, contains_bangla, raw_weight, explanation)


def severity_for_weight(weight: int) -> str:
    if weight >= 6:
        return SEVERITY_HIGH
    if weight >= 3:
        return SEVERITY_MEDIUM
    if weight >= 1:
        return SEVERITY_LOW
    return SEVERITY_NONE


def analysis_to_evidence(analysis: MessageAnalysis, target: str = "submitted message") -> Evidence:
    severity = severity_for_weight(analysis.raw_weight)
    status = STATUS_COMPLETED if analysis.indicators else STATUS_NOT_FOUND
    result = f"{analysis.message_type}: {len(analysis.indicators)} indicator(s) found." if analysis.indicators else "No scam language indicators found."
    return Evidence.build(SOURCE, target, status, severity, result, analysis.to_dict())
