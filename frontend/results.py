"""Results page: overview, evidence, AI analysis and the real agent timeline."""
from __future__ import annotations

import streamlit as st

from database import repository
from frontend.components import build_markdown_report, contribution_chart, evidence_card, format_dt, get_lang, hud, level_badge, result_json, risk_gauge, verdict_banner
from utils.language import t


def _load() -> dict | None:
    params = st.query_params
    if "id" in params:
        try:
            record = repository.get_investigation(int(params["id"]))
        except (TypeError, ValueError):
            record = None
        if record:
            return record
    selected = st.session_state.get("selected_investigation_id")
    last = st.session_state.get("last_result")
    if selected and (not last or last.get("investigation_id") != selected):
        record = repository.get_investigation(int(selected))
        if record:
            return record
    return last


def render() -> None:
    lang = get_lang()
    result = _load()
    if not result:
        st.info("No investigation selected. Run one from Home or open a record from History.")
        if st.button("Go to Home"):
            st.switch_page("frontend/home_page.py")
        return

    risk, report = result["risk"], result["report"]
    st.markdown(f'<div class="hx-hero"><div class="eyebrow">// {t("dossier", lang)} · #{result.get("investigation_id") or "—"}</div></div>', unsafe_allow_html=True)
    st.markdown(
        f'<span class="ss-pill">{result["input_type"]}</span><span class="ss-pill">{format_dt(result.get("created_at", ""))}</span>'
        f'<span class="ss-pill">Planner: {result.get("planner", "")}{" · " + result["model"] if result.get("model") else ""}</span><span class="ss-pill">Report: {report.get("generator", "")}</span>'
        f'<span class="ss-pill">{result.get("tool_calls", 0)} tool calls · {result.get("duration_ms", 0)} ms</span>',
        unsafe_allow_html=True,
    )
    completed = len(risk.get("sources_completed", []))
    verdict_banner(risk["level"], lang, f"{t('hud_target', lang)}: {result.get('target', '')}")
    if result.get("degraded"):
        st.info(t("degraded_notice", lang), icon="ℹ️")

    g, m = st.columns([1, 2])
    with g:
        st.plotly_chart(risk_gauge(risk["score"], risk["level"]), width="stretch", config={"displayModeBar": False})
    with m:
        hud([
            (t("risk_score", lang), f"{risk['score']}/100", {"High": "red", "Suspicious": "red", "Guarded": "", "Low": "neon"}[risk["level"]]),
            (t("risk_level", lang), t("level_" + risk["level"], lang), ""),
            (t("confidence", lang), t("conf_" + risk["confidence"], lang), "cyan"),
            (t("status", lang), f"{risk['investigation_status']} · {completed} src", ""),
        ])
        st.markdown(f"**{t('summary', lang)}:** {report.get('summary', '')}")

    tab1, tab2, tab3, tab4 = st.tabs([t("tab_overview", lang), t("tab_evidence", lang), t("tab_ai", lang), t("tab_investigation", lang)])

    with tab1:
        st.markdown(f"#### {t('indicators', lang)}")
        indicators = report.get("indicators_explained") or []
        if indicators:
            for ind in indicators:
                st.markdown(f"- ⚠️ {ind}")
        else:
            st.markdown("- —")
        st.markdown(f"#### {t('actions', lang)}")
        for n, action in enumerate(report.get("recommended_actions", []), 1):
            st.markdown(f"{n}. {action}")
        st.markdown("#### Score breakdown")
        st.plotly_chart(contribution_chart(risk.get("contributions", [])), width="stretch", config={"displayModeBar": False})
        for c in risk.get("contributions", []):
            st.caption(f"{c['group']}: {c['points']}/{c['maximum']} — {c['basis']}")
        for note in risk.get("notes", []):
            st.caption(f"ℹ️ {note}")

    with tab2:
        st.caption("Each check is shown with its real status: a match is positive evidence; 'no match' is not proof of safety; unavailable or unconfigured checks contribute nothing.")
        for e in result["evidence"]:
            evidence_card(e)
            with st.expander("Details", expanded=False):
                st.json(e.get("details", {}))

    with tab3:
        st.markdown(f"#### {t('ai_explanation', lang)}")
        st.write(report.get("explanation", ""))
        if result.get("agent_interpretation"):
            st.markdown("**Agent interpretation (during investigation):**")
            st.write(result["agent_interpretation"])
        ai = next((e.get("details", {}).get("ai_analysis") for e in result["evidence"] if e.get("source_key") == "message" and e.get("details", {}).get("ai_analysis")), None)
        if ai:
            st.markdown("**AI message classification:**")
            st.json(ai)
        st.caption(report.get("uncertainty_note") or t("disclaimer", lang))

    with tab4:
        st.markdown(f"#### {t('timeline', lang)}")
        icons = {"success": "✅", "info": "ℹ️", "failed": "❌", "skipped": "⏭️", "rejected": "🚫", "not_configured": "⚫", "unavailable": "🟡", "not_found": "✅"}
        for s in result["timeline"]:
            tool = f" · `{s['tool_name']}`" if s.get("tool_name") else ""
            dur = f" · {s['duration_ms']} ms" if s.get("duration_ms") else ""
            st.markdown(f"{icons.get(s['status'], '•')} **{s['step_name']}**{tool}{dur}  \n<span class='ss-muted'>{s.get('details', '')}</span>", unsafe_allow_html=True)

    st.markdown("---")
    md = build_markdown_report(result, lang)
    a1, a2, a3, a4 = st.columns([1, 1, 1, 1])
    with a1:
        st.download_button(t("download_report", lang) + " (.md)", md, file_name=f"scamsathi_report_{result.get('investigation_id') or 'latest'}.md", mime="text/markdown", width="stretch")
    with a2:
        st.download_button("JSON", result_json(result), file_name=f"scamsathi_report_{result.get('investigation_id') or 'latest'}.json", mime="application/json", width="stretch")
    with a3:
        if st.button(t("copy_report", lang), width="stretch"):
            st.session_state["show_copy"] = not st.session_state.get("show_copy", False)
    with a4:
        if result.get("investigation_id") and st.button(t("delete_record", lang), type="secondary", width="stretch"):
            repository.delete_investigation(int(result["investigation_id"]))
            st.session_state.pop("last_result", None)
            st.session_state.pop("selected_investigation_id", None)
            st.query_params.clear()
            st.success("Record deleted.")
            st.switch_page("frontend/history_page.py")
    if st.session_state.get("show_copy"):
        st.caption("Use the copy icon in the top-right corner of the block below.")
        st.code(md, language="markdown")
