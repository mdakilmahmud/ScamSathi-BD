"""ScamSathi BD — Streamlit entry point."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from config.constants import APP_NAME  # noqa: E402
from database.db import init_db  # noqa: E402
from frontend.components import inject_css, sidebar_brand  # noqa: E402

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
init_db()
inject_css()
st.session_state.setdefault("lang", "en")

pages = {
    "Home": [
        st.Page("frontend/home_page.py", title="New Investigation", icon="🔎", default=True),
        st.Page("frontend/results_page.py", title="Results", icon="📋"),
    ],
    "Investigations": [
        st.Page("frontend/history_page.py", title="History", icon="🕘"),
        st.Page("frontend/statistics_page.py", title="Statistics", icon="📊"),
    ],
    "Information": [
        st.Page("frontend/how_page.py", title="How It Works", icon="🧭"),
        st.Page("frontend/about_page.py", title="About Us", icon="ℹ️"),
    ],
    "Settings": [
        st.Page("frontend/settings_page.py", title="Settings", icon="⚙️"),
    ],
}
sidebar_brand()
st.navigation(pages).run()
