"""How it works, About, and Settings pages."""
from __future__ import annotations

import streamlit as st

from config.constants import MAX_TOOL_CALLS, RISK_LEVELS, WEIGHTS
from config.settings import settings
from database import repository
from frontend.components import get_lang
from utils.language import t


def how_it_works() -> None:
    st.markdown("### How It Works")
    st.markdown(
        """
ScamSathi BD is **not** a chatbot and **not** a one-API URL checker. Each investigation runs an agentic workflow:

1. **Understand** — the submission is validated (length, scheme, private-network and `javascript:`/`file:` rejection) and classified as URL, message, email or mixed. URLs are extracted and normalised.
2. **Plan** — a Gemini function-calling agent receives the content (as untrusted data) and the list of declared tools.
3. **Act** — the agent requests tools; Python validates every argument and executes the call. URL tools only accept URLs extracted from the submission.
4. **Observe & decide** — tool results are returned to the agent, which decides whether another check adds value, within a hard budget of **%d tool calls**.
5. **Score** — a deterministic Python risk engine combines normalised evidence. The LLM never sets the score.
6. **Explain** — Gemini writes the explanation in Bangla or English from the evidence only; a template is used when Gemini is unavailable.
7. **Remember** — a minimised record is saved to SQLite so you can revisit or delete it.

The app **never visits** a submitted URL. It only consults security-intelligence APIs.
"""
        % MAX_TOOL_CALLS
    )
    st.markdown("#### Tools the agent may call")
    st.table(
        [
            {"Tool": "analyze_message", "What it does": "Bilingual scam-language indicators (urgency, prize, OTP/PIN, impersonation, payment pressure, job fraud)"},
            {"Tool": "extract_urls", "What it does": "Lists validated URLs found in the text"},
            {"Tool": "get_domain_indicators", "What it does": "Offline domain features: brand lookalikes, abused TLDs, punycode, IP hosts, shorteners"},
            {"Tool": "check_safe_browsing", "What it does": "Google Safe Browsing threat lists (phishing, malware)"},
            {"Tool": "check_virustotal", "What it does": "VirusTotal multi-engine URL reputation"},
            {"Tool": "check_urlhaus", "What it does": "URLhaus malware-distribution reports (optional)"},
            {"Tool": "calculate_risk", "What it does": "Deterministic scoring — run by the orchestrator, not the model"},
            {"Tool": "generate_report", "What it does": "Structured bilingual report — run by the orchestrator"},
        ]
    )
    st.markdown("#### Risk scoring model")
    st.table([{"Evidence group": k, "Maximum contribution": v} for k, v in WEIGHTS.items()] + [{"Evidence group": "Total", "Maximum contribution": sum(WEIGHTS.values())}])
    st.caption("Floors: strong message indicators (weight × 9, cap 80) and brand-lookalike domain features (weight × 4, cap 45) can raise the score because an OTP request or a fake bKash domain is dangerous regardless of list reputation. Only API evidence can push a score above those caps.")
    st.table([{"Score": f"{lo}–{hi - 1}", "Category": label} for lo, hi, label in RISK_LEVELS])
    st.markdown("**Risk ≠ confidence.** Risk describes how concerning the evidence is; confidence describes how complete the investigation was (which sources actually answered).")


def about() -> None:
    st.markdown("### About ScamSathi BD")
    st.markdown(
        """
People in Bangladesh receive fake bKash/Nagad/bank messages, fake job circulars, prize scams and phishing links every day.
ScamSathi BD lets anyone paste a suspicious link or message and get an evidence-based risk assessment with a plain-language explanation in Bangla or English.

**Core principle:** external security intelligence provides evidence, deterministic Python logic evaluates it, and the LLM explains it.

**Limitations**
- "No match" from a security provider does not prove a site is safe; new scam domains are often unknown for days.
- Message indicators are warning signs, not proof of fraud.
- Results depend on third-party API availability and quotas.
- This is an automated assessment, not a legal finding.

**Data & privacy** — submitted URLs/text may be sent to Google Safe Browsing, VirusTotal, URLhaus and the Gemini API. History stores a minimised copy (long digit sequences masked) which you can delete at any time.
"""
    )


def settings_page() -> None:
    lang = get_lang()
    st.markdown("### Settings")
    st.markdown("#### Language")
    st.write("Use the selector in the sidebar. Current:", "বাংলা" if lang == "bn" else "English")

    st.markdown("#### Service status")
    rows = [
        {"Service": "Gemini (agent + report)", "Configured": settings.gemini_configured, "Env var": "GEMINI_API_KEY"},
        {"Service": "Google Safe Browsing", "Configured": settings.safe_browsing_configured, "Env var": "GOOGLE_SAFE_BROWSING_KEY"},
        {"Service": "VirusTotal", "Configured": settings.virustotal_configured, "Env var": "VIRUSTOTAL_API_KEY"},
        {"Service": "URLhaus (optional)", "Configured": settings.urlhaus_configured, "Env var": "URLHAUS_AUTH_KEY"},
    ]
    st.table([{**r, "Configured": "✅ yes" if r["Configured"] else "⚫ no"} for r in rows])
    if st.button("Test Gemini connectivity"):
        from integrations.gemini import ping

        ok, msg = ping()
        (st.success if ok else st.error)(msg)

    st.markdown("#### Privacy")
    st.write("Minimised content retention:", "enabled" if settings.retain_submitted_content else "disabled", "(set `RETAIN_SUBMITTED_CONTENT` in `.env`)")
    st.caption(t("consent", lang))
    with st.popover("Delete all history"):
        st.warning("This permanently deletes every saved investigation.")
        if st.button("Yes, delete everything", type="primary", key="settings_delete_all"):
            n = repository.delete_all()
            st.success(f"Deleted {n} record(s).")
