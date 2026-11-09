"""Shared UI pieces: CSS, badges, gauge, report text."""
from __future__ import annotations

import json
from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from backend.evidence import status_label
from config.constants import APP_NAME, SUPPORTED_LANGUAGES, TAGLINE
from utils.language import t

LEVEL_COLORS = {"Low": "#22C55E", "Guarded": "#F59E0B", "Suspicious": "#F97316", "High": "#EF4444"}
STATUS_ICONS = {"completed": "✓", "running": "●", "pending": " ", "failed": "✗", "skipped": "–"}
EVIDENCE_STATUS_ICONS = {"completed": "🔴", "not_found": "⚪", "unavailable": "🟡", "failed": "🟡", "not_configured": "⚫", "skipped": "⚫"}

CSS = """
<style>
:root { --navy:#0B1220; --card:#111A2E; --border:#1E2A44; --teal:#14B8A6; --blue:#3B82F6; --text:#E5E7EB; --muted:#94A3B8; }
.stApp { background: radial-gradient(1200px 600px at 10% -10%, #10213f 0%, var(--navy) 55%); }
section[data-testid="stSidebar"] { background:#0A101C; border-right:1px solid var(--border); }
.ss-brand { font-size:1.35rem; font-weight:800; letter-spacing:.3px; color:#fff; }
.ss-brand span { color:var(--teal); }
.ss-tagline { color:var(--muted); font-size:.85rem; margin-top:-6px; }
.ss-hero h1 { font-size:2.4rem; line-height:1.15; margin-bottom:.4rem; color:#fff; }
.ss-hero p { color:var(--muted); font-size:1.05rem; max-width:720px; }
.ss-card { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:18px 20px; height:100%; }
.ss-card h4 { margin:0 0 6px 0; color:#fff; font-size:1rem; }
.ss-card p { margin:0; color:var(--muted); font-size:.92rem; }
.ss-badge { display:inline-block; padding:4px 12px; border-radius:999px; font-weight:700; font-size:.85rem; color:#0B1220; }
.ss-pill { display:inline-block; padding:2px 10px; border-radius:999px; font-size:.78rem; border:1px solid var(--border); color:var(--muted); margin-right:6px; }
.ss-mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0A101C; border:1px solid var(--border); border-radius:12px; padding:16px 18px; color:#cbd5e1; font-size:.92rem; line-height:1.7; white-space:pre-wrap; }
.ss-mono .ok { color:#22C55E; } .ss-mono .run { color:#F59E0B; } .ss-mono .fail { color:#EF4444; } .ss-mono .skip { color:#64748B; }
.ss-safety li { color:var(--muted); }
.ss-ev { background:var(--card); border:1px solid var(--border); border-left:4px solid #334155; border-radius:10px; padding:12px 16px; margin-bottom:10px; }
.ss-ev.high { border-left-color:#EF4444; } .ss-ev.medium { border-left-color:#F97316; } .ss-ev.low { border-left-color:#F59E0B; }
.ss-ev.unavailable, .ss-ev.failed { border-left-color:#F59E0B; opacity:.9; } .ss-ev.not_configured, .ss-ev.skipped { border-left-color:#475569; opacity:.8; }
.ss-ev .src { font-weight:700; color:#fff; } .ss-ev .st { color:var(--muted); font-size:.82rem; margin-left:8px; }
.ss-ev .res { color:#cbd5e1; margin-top:4px; font-size:.93rem; }
.ss-muted { color:var(--muted); font-size:.85rem; }
div[data-testid="stMetricValue"] { color:#fff; }
.stButton>button[kind="primary"] { background:linear-gradient(90deg,var(--blue),var(--teal)); border:0; font-weight:700; }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def get_lang() -> str:
    return st.session_state.get("lang", "en")


def sidebar_brand() -> None:
    with st.sidebar:
        st.markdown(f'<div class="ss-brand">🛡️ Scam<span>Sathi</span> BD</div><div class="ss-tagline">{t("tagline", get_lang())}</div>', unsafe_allow_html=True)
        st.markdown("")
        codes = list(SUPPORTED_LANGUAGES)
        current = get_lang()
        chosen = st.selectbox("Language / ভাষা", codes, index=codes.index(current), format_func=lambda c: SUPPORTED_LANGUAGES[c], key="lang_select")
        if chosen != current:
            st.session_state["lang"] = chosen
            st.rerun()


def level_badge(level: str, lang: str) -> str:
    color = LEVEL_COLORS.get(level, "#64748B")
    return f'<span class="ss-badge" style="background:{color}">{t("level_" + level, lang)}</span>'


def risk_gauge(score: int, level: str) -> go.Figure:
    color = LEVEL_COLORS.get(level, "#64748B")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100", "font": {"color": "#fff", "size": 40}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#94A3B8", "tickfont": {"color": "#94A3B8"}},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#111A2E",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 20], "color": "rgba(34,197,94,.25)"},
                {"range": [20, 40], "color": "rgba(245,158,11,.25)"},
                {"range": [40, 70], "color": "rgba(249,115,22,.25)"},
                {"range": [70, 100], "color": "rgba(239,68,68,.25)"},
            ],
        },
    ))
    fig.update_layout(height=230, margin=dict(l=20, r=20, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)", font={"color": "#E5E7EB"})
    return fig


def contribution_chart(contributions: list[dict]) -> go.Figure:
    labels = {"safe_browsing": "Safe Browsing", "virustotal": "VirusTotal", "urlhaus": "URLhaus", "domain": "Domain", "message": "Message"}
    names = [labels.get(c["group"], c["group"]) for c in contributions]
    fig = go.Figure()
    fig.add_bar(x=names, y=[c["maximum"] for c in contributions], name="Maximum", marker_color="#1E2A44")
    fig.add_bar(x=names, y=[c["points"] for c in contributions], name="Contribution", marker_color="#14B8A6", text=[c["points"] for c in contributions], textposition="outside")
    fig.update_layout(barmode="overlay", height=260, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#E5E7EB"}, legend=dict(orientation="h", y=1.15), yaxis=dict(gridcolor="#1E2A44"))
    return fig


def evidence_card(e: dict) -> None:
    sev_class = e["severity"] if e["status"] == "completed" else e["status"]
    icon = EVIDENCE_STATUS_ICONS.get(e["status"], "⚪")
    target = f'<div class="ss-muted">{e.get("target", "")}</div>' if e.get("target") else ""
    st.markdown(
        f'<div class="ss-ev {sev_class}"><span class="src">{icon} {e["source"]}</span><span class="st">{e["evidence_type"]} · {status_label(e["status"])}</span>{target}<div class="res">{e["result"]}</div></div>',
        unsafe_allow_html=True,
    )


def format_dt(value) -> str:
    if isinstance(value, datetime):
        return value.strftime("%d %b %Y %H:%M")
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).strftime("%d %b %Y %H:%M")
        except ValueError:
            return value
    return str(value)


def build_markdown_report(result: dict, lang: str) -> str:
    risk, report = result["risk"], result["report"]
    lines = [
        f"# {APP_NAME} — Investigation Report",
        f"_{TAGLINE}_",
        "",
        f"**Target:** {result.get('target', '')}  ",
        f"**Input type:** {result['input_type']}  ",
        f"**Date:** {format_dt(result.get('created_at', datetime.now()))}  ",
        f"**Investigation ID:** {result.get('investigation_id') or '—'}",
        "",
        f"## {t('overall', lang)}",
        f"- {t('risk_score', lang)}: **{risk['score']}/100**",
        f"- {t('risk_level', lang)}: **{t('level_' + risk['level'], lang)}**",
        f"- {t('confidence', lang)}: **{t('conf_' + risk['confidence'], lang)}**",
        f"- {t('status', lang)}: **{risk['investigation_status']}**",
        "",
        f"## {t('summary', lang)}",
        report.get("summary", ""),
        "",
        f"## {t('evidence', lang)}",
    ]
    for e in result["evidence"]:
        lines.append(f"- **{e['source']}** ({status_label(e['status'])}): {e['result']}")
    lines += ["", f"## {t('indicators', lang)}"]
    lines += [f"- {i}" for i in report.get("indicators_explained", [])] or ["- —"]
    lines += ["", f"## {t('ai_explanation', lang)}", report.get("explanation", ""), "", f"## {t('actions', lang)}"]
    lines += [f"{n}. {a}" for n, a in enumerate(report.get("recommended_actions", []), 1)]
    lines += ["", f"## {t('timeline', lang)}"]
    for s in result["timeline"]:
        tool = f" `{s['tool_name']}`" if s.get("tool_name") else ""
        lines.append(f"- [{s['status']}] {s['step_name']}{tool} — {s.get('details', '')}")
    lines += ["", "## Score breakdown"]
    for c in risk.get("contributions", []):
        lines.append(f"- {c['group']}: {c['points']}/{c['maximum']} ({c['basis']})")
    for n in risk.get("notes", []):
        lines.append(f"- _{n}_")
    lines += ["", f"> {report.get('uncertainty_note') or t('disclaimer', lang)}", "", f"_Report generator: {report.get('generator', 'template')} · Planner: {result.get('planner', '')}_"]
    return "\n".join(lines)


def result_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)
