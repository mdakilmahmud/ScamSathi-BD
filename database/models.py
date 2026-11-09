"""ORM models: investigations, evidence, agent_logs."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    investigation_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    submitted_content: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[str] = mapped_column(String(255), default="")
    input_type: Mapped[str] = mapped_column(String(32))
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    language: Mapped[str] = mapped_column(String(8), default="en")
    planner: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    risk_json: Mapped[str] = mapped_column(Text, default="{}")
    report_json: Mapped[str] = mapped_column(Text, default="{}")
    classification_json: Mapped[str] = mapped_column(Text, default="{}")

    evidence: Mapped[list["EvidenceRecord"]] = relationship(back_populates="investigation", cascade="all, delete-orphan", order_by="EvidenceRecord.evidence_id")
    logs: Mapped[list["AgentLog"]] = relationship(back_populates="investigation", cascade="all, delete-orphan", order_by="AgentLog.log_id")


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(64))
    source_key: Mapped[str] = mapped_column(String(32))
    evidence_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(2048), default="")
    status: Mapped[str] = mapped_column(String(32))
    result: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    raw_response: Mapped[str] = mapped_column(Text, default="{}")
    checked_at: Mapped[str] = mapped_column(String(40), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    investigation: Mapped["Investigation"] = relationship(back_populates="evidence")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    log_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.investigation_id", ondelete="CASCADE"), index=True)
    step_name: Mapped[str] = mapped_column(String(128))
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    details: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[str] = mapped_column(String(40), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    investigation: Mapped["Investigation"] = relationship(back_populates="logs")
