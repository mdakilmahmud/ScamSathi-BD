"""History page: previous investigations."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from database import repository
from frontend.components import LEVEL_COLORS, format_dt, get_lang
from utils.language import t


def render() -> None:
    lang = get_lang()
    st.markdown(f"### {t('history', lang)}")
    rows = repository.list_investigations(limit=200)
    if not rows:
        st.info(t("no_history", lang))
        return

    df = pd.DataFrame([
        {"ID": r["investigation_id"], "Date": format_dt(r["created_at"]), "Target": r["target"], "Type": r["input_type"], "Risk": f"{r['risk_level']} ({r['risk_score']})", "Confidence": r["confidence"], "Status": r["status"], "Lang": r["language"]}
        for r in rows
    ])

    def _color(val: str):
        for level, color in LEVEL_COLORS.items():
            if str(val).startswith(level):
                return f"color:{color}; font-weight:700"
        return ""

    st.dataframe(df.style.map(_color, subset=["Risk"]), use_container_width=True, hide_index=True)

    st.markdown("#### Open a saved report")
    options = {f"#{r['investigation_id']} · {format_dt(r['created_at'])} · {r['target'][:40]} · {r['risk_level']}": r["investigation_id"] for r in rows}
    choice = st.selectbox("Investigation", list(options), label_visibility="collapsed")
    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        if st.button("Open report", type="primary", use_container_width=True):
            st.session_state["selected_investigation_id"] = options[choice]
            st.session_state.pop("last_result", None)
            st.query_params["id"] = str(options[choice])
            st.switch_page("frontend/results_page.py")
    with c2:
        if st.button("Delete", use_container_width=True):
            repository.delete_investigation(options[choice])
            st.rerun()
    with c3:
        with st.popover("Delete all history"):
            st.warning("This permanently deletes every saved investigation.")
            if st.button("Yes, delete everything", type="primary"):
                repository.delete_all()
                st.rerun()
