"""Aggregate statistics over saved investigations."""
from __future__ import annotations

import plotly.graph_objects as go
import streamlit as st

from database import repository
from frontend.components import LEVEL_COLORS


def _bar(data: dict, colors: dict | None = None, title: str = "") -> go.Figure:
    keys = list(data)
    fig = go.Figure(go.Bar(x=keys, y=[data[k] for k in keys], marker_color=[(colors or {}).get(k, "#3B82F6") for k in keys], text=[data[k] for k in keys], textposition="outside"))
    fig.update_layout(title=title, height=300, margin=dict(l=10, r=10, t=40, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#E5E7EB"}, yaxis=dict(gridcolor="#1E2A44"))
    return fig


def render() -> None:
    st.markdown("### Statistics")
    stats = repository.statistics()
    if not stats["total"]:
        st.info("No investigations yet.")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Total investigations", stats["total"])
    c2.metric("Average risk score", stats["avg_score"])
    c3.metric("High-risk share", f"{round(100 * stats['by_level'].get('High', 0) / stats['total'])}%")
    a, b = st.columns(2)
    with a:
        ordered = {k: stats["by_level"].get(k, 0) for k in ("Low", "Guarded", "Suspicious", "High")}
        st.plotly_chart(_bar(ordered, LEVEL_COLORS, "Risk levels"), width="stretch", config={"displayModeBar": False})
    with b:
        st.plotly_chart(_bar(stats["by_type"], title="Input types"), width="stretch", config={"displayModeBar": False})
    a, b = st.columns(2)
    with a:
        st.plotly_chart(_bar(stats["by_status"], {"Complete": "#22C55E", "Partial": "#F59E0B", "Failed": "#EF4444"}, "Investigation completeness"), width="stretch", config={"displayModeBar": False})
    with b:
        st.markdown("**Source availability** (evidence rows by status)")
        import pandas as pd

        df = pd.DataFrame(stats["source_status"], columns=["Source", "Status", "Count"])
        st.dataframe(df.pivot_table(index="Source", columns="Status", values="Count", fill_value=0), width="stretch")
    st.caption("Statistics describe this installation's saved history only, not real-world scam prevalence.")
