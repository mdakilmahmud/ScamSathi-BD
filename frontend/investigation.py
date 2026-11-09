"""Live investigation progress rendered from real backend events as a terminal log."""
from __future__ import annotations

import html
import time

import streamlit as st

from frontend.components import STATUS_ICONS, terminal
from utils.language import t

_CLASS = {"completed": "ok", "running": "run", "failed": "fail", "skipped": "skip", "pending": "dim"}


class ProgressView:
    """Collects backend events and re-renders a terminal-style log (every line is a real event)."""

    def __init__(self, placeholder, target: str, lang: str):
        self.placeholder = placeholder
        self.target = target
        self.lang = lang
        self.rows: list[dict] = []
        self.index: dict[str, int] = {}
        self.status_text = t("investigating", lang)
        self.started = time.monotonic()
        self.done = False
        self.render()

    def handle(self, event: dict) -> None:
        base_key = f"{event.get('step')}|{event.get('tool') or ''}"
        idx = self.index.get(base_key)
        row = {"step": event.get("step", ""), "status": event.get("status", "pending"), "message": event.get("message", ""), "tool": event.get("tool"), "t": time.strftime("%H:%M:%S")}
        if idx is None:
            self.index[base_key] = len(self.rows)
            self.rows.append(row)
        else:
            row["t"] = self.rows[idx]["t"]
            self.rows[idx] = row
        if event.get("status") == "running":
            self.status_text = f"{event.get('step')}…"
        self.render()

    def finish(self, text: str) -> None:
        self.status_text = text
        self.done = True
        self.render()

    def render(self) -> None:
        lines = [
            f'<span class="dim">$</span> <span class="hl">scamsathi</span> --investigate <span class="dim">--target</span> "{html.escape(self.target)}"',
            f'<span class="dim">[{time.strftime("%H:%M:%S")}] session opened · agent armed · untrusted input isolated</span>',
            "",
        ]
        for row in self.rows:
            icon = STATUS_ICONS.get(row["status"], "   ")
            msg = html.escape(str(row["message"] or ""))
            if len(msg) > 90:
                msg = msg[:87] + "…"
            tool = f' <span class="hl">{html.escape(row["tool"])}</span>' if row.get("tool") else ""
            suffix = f' <span class="dim">— {msg}</span>' if msg else ""
            lines.append(f'<span class="ts">[{row["t"]}]</span> <span class="{_CLASS.get(row["status"], "")}">[{icon}]</span> {html.escape(row["step"])}{tool}{suffix}')
        elapsed = f"{time.monotonic() - self.started:5.1f}s"
        cursor = "" if self.done else '<span class="hx-cursor"></span>'
        lines += ["", f'<span class="dim">{t("agent_status", self.lang)}:</span> <b>{html.escape(self.status_text)}</b> <span class="dim">· {elapsed}</span>{cursor}']
        self.placeholder.markdown(terminal("<br>".join(lines), t("term_title", self.lang)), unsafe_allow_html=True)
