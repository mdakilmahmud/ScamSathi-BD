"""Shared UI pieces: cyber-console CSS, HUD widgets, gauge, report text."""
from __future__ import annotations

import html
import json
from datetime import datetime

import plotly.graph_objects as go
import streamlit as st

from backend.evidence import status_label
from config.constants import APP_NAME, SUPPORTED_LANGUAGES, TAGLINE
from config.settings import settings
from utils.language import t

NEON = "#00FF9C"
CYAN = "#00E5FF"
AMBER = "#FFB020"
RED = "#FF3864"
LEVEL_COLORS = {"Low": NEON, "Guarded": AMBER, "Suspicious": "#FF7A1A", "High": RED}
STATUS_ICONS = {"completed": "OK ", "running": ">> ", "pending": "   ", "failed": "ERR", "skipped": "-- "}
EVIDENCE_STATUS_ICONS = {"completed": "▣", "not_found": "▢", "unavailable": "◈", "failed": "◈", "not_configured": "◌", "skipped": "◌"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Rajdhani:wght@500;600;700&family=Noto+Sans+Bengali:wght@400;600&display=swap');
:root { --bg:#030806; --panel:#07110D; --panel2:#0A1A13; --line:#0F3B2A; --neon:#00FF9C; --cyan:#00E5FF; --amber:#FFB020; --red:#FF3864; --text:#D7FFE9; --muted:#6FA28A; }
html, body, .stApp, [data-testid="stAppViewContainer"] * { font-family:'JetBrains Mono', ui-monospace, Menlo, 'Noto Sans Bengali', monospace; }
h1,h2,h3,h4, .hx-title { font-family:'Rajdhani','JetBrains Mono',sans-serif !important; letter-spacing:.06em; text-transform:uppercase; }
.stApp {
  background-color: var(--bg);
  background-image:
    radial-gradient(900px 500px at 15% -10%, rgba(0,255,156,.10) 0%, rgba(0,0,0,0) 60%),
    radial-gradient(700px 400px at 100% 0%, rgba(0,229,255,.08) 0%, rgba(0,0,0,0) 60%),
    linear-gradient(rgba(0,255,156,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,255,156,.045) 1px, transparent 1px);
  background-size: auto, auto, 32px 32px, 32px 32px;
}
.stApp::before { content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
  background: repeating-linear-gradient(0deg, rgba(0,0,0,.18) 0px, rgba(0,0,0,.18) 1px, transparent 1px, transparent 3px); mix-blend-mode:multiply; }
section[data-testid="stSidebar"] { background:#040B08; border-right:1px solid var(--line); }
section[data-testid="stSidebar"] * { color:var(--text); }
[data-testid="stHeader"] { background:transparent; }
.hx-brand { font-family:'Rajdhani',sans-serif; font-size:1.55rem; font-weight:700; letter-spacing:.12em; color:#fff; text-transform:uppercase; }
.hx-brand span { color:var(--neon); text-shadow:0 0 12px rgba(0,255,156,.8); }
.hx-tag { color:var(--muted); font-size:.78rem; letter-spacing:.08em; margin-top:-4px; }
.hx-led { display:flex; justify-content:space-between; font-size:.74rem; color:var(--muted); padding:3px 0; border-bottom:1px dashed #0F2A1F; }
.hx-led b { color:var(--text); font-weight:600; }
.hx-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }
.hx-dot.on { background:var(--neon); box-shadow:0 0 8px var(--neon); animation:pulse 2.2s infinite; }
.hx-dot.off { background:#2B3A33; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
@keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
@keyframes glow { 0%,100%{box-shadow:0 0 18px rgba(255,56,100,.35), inset 0 0 30px rgba(255,56,100,.08)} 50%{box-shadow:0 0 42px rgba(255,56,100,.75), inset 0 0 40px rgba(255,56,100,.15)} }
@keyframes sweep { 0%{transform:translateX(-100%)} 100%{transform:translateX(400%)} }
.hx-hero { padding:6px 0 4px 0; }
.hx-hero .eyebrow { color:var(--neon); font-size:.78rem; letter-spacing:.3em; text-transform:uppercase; }
.hx-hero h1 { font-size:2.6rem; line-height:1.05; margin:.2rem 0 .3rem 0; color:#fff; text-shadow:0 0 24px rgba(0,255,156,.25); }
.hx-hero p { color:var(--muted); font-size:.95rem; max-width:760px; margin:0; }
.hx-cursor { display:inline-block; width:.6em; height:1.05em; background:var(--neon); vertical-align:-0.15em; margin-left:4px; animation:blink 1s steps(1) infinite; box-shadow:0 0 10px var(--neon); }
.hx-hud { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:10px; margin:14px 0 6px 0; }
.hx-stat { position:relative; overflow:hidden; background:linear-gradient(180deg, rgba(0,255,156,.06), rgba(0,0,0,0)); border:1px solid var(--line); border-radius:6px; padding:10px 14px; }
.hx-stat::after { content:""; position:absolute; left:0; top:0; width:25%; height:1px; background:linear-gradient(90deg, transparent, var(--neon), transparent); animation:sweep 3.5s linear infinite; }
.hx-stat .k { font-size:.64rem; letter-spacing:.14em; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.hx-stat .v { font-family:'Rajdhani',sans-serif; font-size:1.45rem; font-weight:700; color:#fff; line-height:1.1; overflow-wrap:anywhere; }
.hx-stat .v.neon { color:var(--neon); text-shadow:0 0 14px rgba(0,255,156,.6); }
.hx-stat .v.red { color:var(--red); text-shadow:0 0 14px rgba(255,56,100,.6); }
.hx-stat .v.cyan { color:var(--cyan); text-shadow:0 0 14px rgba(0,229,255,.6); }
.hx-term { background:#020604; border:1px solid var(--line); border-radius:8px; box-shadow:0 0 0 1px rgba(0,255,156,.05), 0 0 30px rgba(0,255,156,.08); overflow:hidden; }
.hx-term .bar { display:flex; align-items:center; gap:8px; padding:7px 12px; background:#061009; border-bottom:1px solid var(--line); font-size:.74rem; color:var(--muted); letter-spacing:.08em; }
.hx-term .bar i { width:10px; height:10px; border-radius:50%; display:inline-block; }
.hx-term .body { padding:14px 16px; color:#BFFFE0; font-size:.86rem; line-height:1.75; white-space:pre-wrap; }
.hx-term .ts { color:#3F7A61; } .hx-term .ok { color:var(--neon); } .hx-term .run { color:var(--amber); } .hx-term .fail { color:var(--red); } .hx-term .skip { color:#4E7F69; } .hx-term .dim { color:var(--muted); }
.hx-term .hl { color:var(--cyan); }
.hx-card { background:linear-gradient(160deg, rgba(7,17,13,.95), rgba(3,8,6,.95)); border:1px solid var(--line); border-radius:8px; padding:16px 18px; height:100%; position:relative; }
.hx-card::before { content:""; position:absolute; left:0; top:12px; bottom:12px; width:2px; background:var(--neon); box-shadow:0 0 10px var(--neon); }
.hx-card .num { color:var(--neon); font-size:.72rem; letter-spacing:.3em; }
.hx-card h4 { margin:2px 0 6px 0; color:#fff; font-size:1.05rem; }
.hx-card p { margin:0; color:var(--muted); font-size:.86rem; }
.hx-verdict { border-radius:8px; padding:14px 18px; margin:8px 0 12px 0; border:1px solid; font-family:'Rajdhani',sans-serif; letter-spacing:.14em; text-transform:uppercase; font-weight:700; font-size:1.15rem; }
.hx-verdict small { display:block; font-family:'JetBrains Mono',monospace; letter-spacing:.02em; text-transform:none; font-weight:400; font-size:.8rem; opacity:.85; margin-top:4px; }
.hx-verdict.High { color:#fff; background:rgba(255,56,100,.12); border-color:var(--red); animation:glow 1.8s ease-in-out infinite; }
.hx-verdict.Suspicious { color:#FFD8B0; background:rgba(255,122,26,.10); border-color:#FF7A1A; box-shadow:0 0 24px rgba(255,122,26,.3); }
.hx-verdict.Guarded { color:#FFE7B0; background:rgba(255,176,32,.08); border-color:var(--amber); box-shadow:0 0 18px rgba(255,176,32,.25); }
.hx-verdict.Low { color:#CFFFEA; background:rgba(0,255,156,.07); border-color:var(--neon); box-shadow:0 0 18px rgba(0,255,156,.25); }
.ss-badge { display:inline-block; padding:4px 12px; border-radius:4px; font-weight:800; font-size:.8rem; letter-spacing:.12em; color:#030806; text-transform:uppercase; }
.ss-pill { display:inline-block; padding:2px 10px; border-radius:4px; font-size:.72rem; border:1px solid var(--line); color:var(--muted); margin-right:6px; letter-spacing:.04em; }
.ss-ev { background:var(--panel); border:1px solid var(--line); border-left:3px solid #2B4A3C; border-radius:6px; padding:10px 14px; margin-bottom:8px; }
.ss-ev.high { border-left-color:var(--red); box-shadow:inset 0 0 30px rgba(255,56,100,.08); } .ss-ev.medium { border-left-color:#FF7A1A; } .ss-ev.low { border-left-color:var(--amber); }
.ss-ev.none { border-left-color:var(--neon); }
.ss-ev.unavailable, .ss-ev.failed { border-left-color:var(--amber); opacity:.9; } .ss-ev.not_configured, .ss-ev.skipped { border-left-color:#2B4A3C; opacity:.75; }
.ss-ev .src { font-weight:700; color:#fff; } .ss-ev .st { color:var(--muted); font-size:.76rem; margin-left:8px; letter-spacing:.04em; }
.ss-ev .res { color:#BFFFE0; margin-top:4px; font-size:.88rem; }
.ss-muted { color:var(--muted); font-size:.8rem; }
.ss-mono { font-family:'JetBrains Mono',monospace; }
div[data-testid="stMetric"] { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:8px 12px; }
div[data-testid="stMetricLabel"] p { color:var(--muted) !important; letter-spacing:.14em; font-size:.68rem !important; text-transform:uppercase; }
div[data-testid="stMetricValue"] { color:#fff; font-family:'Rajdhani',sans-serif; font-weight:700; }
.stButton>button[kind="primary"] { background:linear-gradient(90deg, var(--neon), var(--cyan)); color:#03110A; border:0; font-weight:800; letter-spacing:.14em; text-transform:uppercase; box-shadow:0 0 18px rgba(0,255,156,.35); }
.stButton>button[kind="primary"]:hover { box-shadow:0 0 30px rgba(0,255,156,.7); color:#000; }
.stButton>button[kind="secondary"], .stDownloadButton>button { border:1px solid var(--line) !important; background:var(--panel) !important; color:var(--text) !important; letter-spacing:.06em; }
.stButton>button[kind="secondary"]:hover, .stDownloadButton>button:hover { border-color:var(--neon) !important; color:var(--neon) !important; }
textarea, .stTextArea textarea { background:#020604 !important; color:#BFFFE0 !important; border:1px solid var(--line) !important; font-family:'JetBrains Mono',monospace !important; caret-color:var(--neon); }
.stTextArea textarea:focus { border-color:var(--neon) !important; box-shadow:0 0 0 1px var(--neon), 0 0 18px rgba(0,255,156,.35) !important; }
div[data-testid="stContainer"][data-border="true"], [data-testid="stVerticalBlockBorderWrapper"] > div { border-color:var(--line) !important; }
.stTabs [data-baseweb="tab-list"] { gap:4px; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"] { letter-spacing:.1em; text-transform:uppercase; font-size:.78rem; color:var(--muted); }
.stTabs [aria-selected="true"] { color:var(--neon) !important; }
.stTabs [data-baseweb="tab-highlight"] { background:var(--neon); box-shadow:0 0 10px var(--neon); }
[data-testid="stExpander"] details { border:1px solid var(--line); border-radius:6px; background:var(--panel); }
.stDataFrame, [data-testid="stTable"] { border:1px solid var(--line); border-radius:6px; }
hr { border-color:var(--line) !important; }
a { color:var(--cyan) !important; }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def get_lang() -> str:
    return st.session_state.get("lang", "en")


def _led(label: str, on: bool, detail: str = "") -> str:
    return f'<div class="hx-led"><span><span class="hx-dot {"on" if on else "off"}"></span>{label}</span><b>{detail or ("ONLINE" if on else "OFFLINE")}</b></div>'


def sidebar_brand() -> None:
    with st.sidebar:
        st.markdown(f'<div class="hx-brand">Scam<span>Sathi</span> // BD</div><div class="hx-tag">{t("tagline", get_lang())}</div>', unsafe_allow_html=True)
        st.markdown("")
        codes = list(SUPPORTED_LANGUAGES)
        current = get_lang()
        chosen = st.selectbox("Language / ভাষা", codes, index=codes.index(current), format_func=lambda c: SUPPORTED_LANGUAGES[c], key="lang_select")
        if chosen != current:
            st.session_state["lang"] = chosen
            st.rerun()
        st.markdown("")
        st.markdown(
            '<div class="ss-muted" style="letter-spacing:.2em;font-size:.68rem;margin-bottom:4px">INTEL FEEDS</div>'
            + _led("GEMINI AGENT", settings.gemini_configured, settings.gemini_model if settings.gemini_configured else "")
            + _led("SAFE BROWSING", settings.safe_browsing_configured)
            + _led("VIRUSTOTAL", settings.virustotal_configured, "" if settings.virustotal_configured else "OPTIONAL")
            + _led("URLHAUS", settings.urlhaus_configured, "" if settings.urlhaus_configured else "OPTIONAL"),
            unsafe_allow_html=True,
        )


def terminal(body_html: str, title: str = "scamsathi@bd:~") -> str:
    return (
        '<div class="hx-term"><div class="bar">'
        '<i style="background:#FF3864"></i><i style="background:#FFB020"></i><i style="background:#00FF9C"></i>'
        f'<span style="margin-left:8px">{html.escape(title)}</span></div>'
        f'<div class="body">{body_html}</div></div>'
    )


def hud(stats: list[tuple[str, str, str]]) -> None:
    """stats: (label, value, tone) where tone in {neon, red, cyan, ''}."""
    cells = "".join(f'<div class="hx-stat"><div class="k">{html.escape(k)}</div><div class="v {tone}">{html.escape(str(v))}</div></div>' for k, v, tone in stats)
    st.markdown(f'<div class="hx-hud">{cells}</div>', unsafe_allow_html=True)


def verdict_banner(level: str, lang: str, sub: str = "") -> None:
    st.markdown(f'<div class="hx-verdict {level}">{t("verdict_" + level, lang)}<small>{html.escape(sub)}</small></div>', unsafe_allow_html=True)


def level_badge(level: str, lang: str) -> str:
    color = LEVEL_COLORS.get(level, "#64748B")
    return f'<span class="ss-badge" style="background:{color}">{t("level_" + level, lang)}</span>'


def risk_gauge(score: int, level: str) -> go.Figure:
    color = LEVEL_COLORS.get(level, "#64748B")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100", "font": {"color": color, "size": 42, "family": "Rajdhani, JetBrains Mono, monospace"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#3F7A61", "tickfont": {"color": "#6FA28A", "size": 10}},
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": "#07110D",
            "borderwidth": 1,
            "bordercolor": "#0F3B2A",
            "steps": [
                {"range": [0, 20], "color": "rgba(0,255,156,.12)"},
                {"range": [20, 40], "color": "rgba(255,176,32,.12)"},
                {"range": [40, 70], "color": "rgba(255,122,26,.14)"},
                {"range": [70, 100], "color": "rgba(255,56,100,.18)"},
            ],
            "threshold": {"line": {"color": "#fff", "width": 2}, "thickness": 0.8, "value": score},
        },
    ))
    fig.update_layout(height=230, margin=dict(l=20, r=20, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)", font={"color": "#D7FFE9"})
    return fig


def contribution_chart(contributions: list[dict]) -> go.Figure:
    labels = {"safe_browsing": "Safe Browsing", "virustotal": "VirusTotal", "urlhaus": "URLhaus", "domain": "Domain", "message": "Message"}
    names = [labels.get(c["group"], c["group"]) for c in contributions]
    fig = go.Figure()
    fig.add_bar(x=names, y=[c["maximum"] for c in contributions], name="Maximum", marker_color="#0F3B2A")
    fig.add_bar(x=names, y=[c["points"] for c in contributions], name="Contribution", marker_color=NEON, text=[c["points"] for c in contributions], textposition="outside")
    fig.update_layout(barmode="overlay", height=260, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#D7FFE9", "family": "JetBrains Mono, monospace"}, legend=dict(orientation="h", y=1.15), yaxis=dict(gridcolor="#0F3B2A"))
    return fig


def evidence_card(e: dict) -> None:
    sev_class = e["severity"] if e["status"] == "completed" else e["status"]
    icon = EVIDENCE_STATUS_ICONS.get(e["status"], "▢")
    target = f'<div class="ss-muted">{html.escape(e.get("target", ""))}</div>' if e.get("target") else ""
    st.markdown(
        f'<div class="ss-ev {sev_class}"><span class="src">{icon} {e["source"]}</span><span class="st">{e["evidence_type"]} · {status_label(e["status"])}</span>{target}<div class="res">{html.escape(e["result"])}</div></div>',
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
