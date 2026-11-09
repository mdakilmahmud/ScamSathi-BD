"""Home page: submit a URL or message and watch the real investigation."""
from __future__ import annotations

import streamlit as st

from backend.orchestrator import InvestigationError, run_investigation
from config.settings import settings
from frontend.components import get_lang
from frontend.investigation import ProgressView
from utils.language import t

EXAMPLES = {
    "Prize + OTP (Bangla)": "অভিনন্দন! আপনি ৫০,০০০ টাকা জিতেছেন। পুরস্কার পেতে এখনই আপনার বিকাশ নাম্বার ও OTP প্রদান করুন।",
    "Prize SMS with link": "Congratulations! You have won Tk 50,000. Claim your reward now: http://bkash-offer-claim.xyz/verify",
    "Fake job offer": "Urgent hiring! Work from home, earn Tk 2,000 daily. Pay Tk 500 registration fee to secure the job. Contact now.",
    "Safe Browsing test URL": "http://testsafebrowsing.appspot.com/s/phishing.html",
    "Harmless URL": "https://www.wikipedia.org/",
}


def render() -> None:
    lang = get_lang()
    st.markdown(f'<div class="ss-hero"><h1>{t("hero", lang)}</h1><p>{t("hero_sub", lang)}</p></div>', unsafe_allow_html=True)

    if not settings.gemini_configured:
        st.info(t("degraded_notice", lang), icon="ℹ️")

    with st.container(border=True):
        st.session_state.setdefault("content_input", st.session_state.get("draft_content", ""))

        def _apply_example() -> None:
            picked = st.session_state.get("example_pick", "—")
            if picked != "—":
                st.session_state["content_input"] = EXAMPLES[picked]

        st.selectbox("Try an example (optional)", ["—"] + list(EXAMPLES), key="example_pick", on_change=_apply_example)
        content = st.text_area("Content", placeholder=t("input_placeholder", lang), height=150, label_visibility="collapsed", key="content_input")
        col_mode, col_btn = st.columns([3, 1])
        with col_mode:
            mode_labels = {"auto": t("mode_auto", lang), "url": t("mode_url", lang), "message": t("mode_message", lang)}
            mode = st.radio(t("input_mode", lang), list(mode_labels), format_func=mode_labels.get, horizontal=True, key="mode_input")
        consent = st.checkbox(t("consent", lang), value=st.session_state.get("consent", False), key="consent")
        with col_btn:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            go = st.button(t("investigate", lang), type="primary", use_container_width=True)

    if go:
        if not content.strip():
            st.warning(t("input_placeholder", lang))
        elif not consent:
            st.warning(t("consent_required", lang))
        else:
            st.session_state["draft_content"] = content
            _run(content, mode, lang)
            return

    c1, c2, c3 = st.columns(3)
    for col, key in zip((c1, c2, c3), ("ai", "sources", "lang")):
        with col:
            st.markdown(f'<div class="ss-card"><h4>{t(f"card_{key}_title", lang)}</h4><p>{t(f"card_{key}_body", lang)}</p></div>', unsafe_allow_html=True)

    st.markdown("")
    st.markdown(f"**{t('safety_title', lang)}**")
    st.markdown(f'<ul class="ss-safety"><li>{t("safety_otp", lang)}</li><li>{t("safety_pin", lang)}</li><li>{t("safety_verify", lang)}</li></ul>', unsafe_allow_html=True)
    st.caption(t("disclaimer", lang))


def _run(content: str, mode: str, lang: str) -> None:
    target = " ".join(content.split())
    target = target if len(target) <= 70 else target[:67] + "..."
    placeholder = st.empty()
    view = ProgressView(placeholder, target, lang)
    try:
        result = run_investigation(content, mode=mode, language=lang, consent_to_share=True, on_event=view.handle)
    except InvestigationError as exc:
        view.finish("Stopped")
        st.error(str(exc))
        return
    except Exception as exc:  # surface unexpected failures honestly
        view.finish("Failed")
        st.error(f"Investigation failed: {exc.__class__.__name__}: {exc}")
        return
    view.finish("Complete")
    st.session_state["last_result"] = result
    st.session_state["selected_investigation_id"] = result.get("investigation_id")
    st.switch_page("frontend/results_page.py")
