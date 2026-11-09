"""Live investigation progress rendered from real backend events."""
from __future__ import annotations

import html

import streamlit as st

from frontend.components import STATUS_ICONS
from utils.language import t

_CLASS = {"completed": "ok", "running": "run", "failed": "fail", "skipped": "skip", "pending": ""}


class ProgressView:
    """Collects backend events and re-renders a terminal-style checklist."""

    def __init__(self, placeholder, target: str, lang: str):
        self.placeholder = placeholder
        self.target = target
        self.lang = lang
        self.rows: list[dict] = []
        self.index: dict[str, int] = {}
        self.status_text = t("investigating", lang)
        self.render()

    def handle(self, event: dict) -> None:
        key = f"{event.get('step')}|{event.get('tool') or ''}|{event.get('message') if event.get('tool') and event.get('status') == 'running' else ''}"
        base_key = f"{event.get('step')}|{event.get('tool') or ''}"
        idx = self.index.get(base_key)
        row = {"step": event.get("step", ""), "status": event.get("status", "pending"), "message": event.get("message", ""), "tool": event.get("tool")}
        if idx is None:
            self.index[base_key] = len(self.rows)
            self.rows.append(row)
        else:
            self.rows[idx] = row
        if event.get("status") == "running":
            self.status_text = f"{event.get('step')}…"
        self.render()

    def finish(self, text: str) -> None:
        self.status_text = text
        self.render()

    def render(self) -> None:
        lines = [f"<b>{t('progress_title', self.lang).upper()}</b>", "", f"Target: {html.escape(self.target)}", ""]
        for row in self.rows:
            icon = STATUS_ICONS.get(row["status"], " ")
            msg = html.escape(str(row["message"] or ""))
            if len(msg) > 90:
                msg = msg[:87] + "…"
            suffix = f' <span class="skip">— {msg}</span>' if msg else ""
            lines.append(f'<span class="{_CLASS.get(row["status"], "")}">[{icon}]</span> {html.escape(row["step"])}{suffix}')
        lines += ["", f"{t('agent_status', self.lang)}: <b>{html.escape(self.status_text)}</b>"]
        self.placeholder.markdown('<div class="ss-mono">' + "<br>".join(lines) + "</div>", unsafe_allow_html=True)
