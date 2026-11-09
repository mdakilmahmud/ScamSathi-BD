"""Persistence helpers for investigation history."""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import func, select

from database.db import init_db, session_scope
from database.models import AgentLog, EvidenceRecord, Investigation


def save_investigation(result: dict, retain_content: bool = True) -> int:
    init_db()
    with session_scope() as session:
        record = Investigation(
            submitted_content=result.get("stored_content", "") if retain_content else "",
            target=result.get("target", "")[:255],
            input_type=result["input_type"],
            risk_score=result["risk"]["score"],
            risk_level=result["risk"]["level"],
            confidence=result["risk"]["confidence"],
            status=result["risk"]["investigation_status"],
            language=result.get("language", "en"),
            planner=result.get("planner", ""),
            risk_json=json.dumps(result["risk"], ensure_ascii=False),
            report_json=json.dumps(result["report"], ensure_ascii=False),
            classification_json=json.dumps(result.get("classification", {}), ensure_ascii=False),
        )
        for e in result["evidence"]:
            record.evidence.append(EvidenceRecord(
                source=e["source"], source_key=e["source_key"], evidence_type=e["evidence_type"], target=e.get("target", ""),
                status=e["status"], result=e["result"], severity=e["severity"],
                raw_response=json.dumps(e.get("details", {}), ensure_ascii=False, default=str), checked_at=e.get("checked_at", ""), duration_ms=e.get("duration_ms", 0),
            ))
        for step in result["timeline"]:
            record.logs.append(AgentLog(step_name=step["step_name"], tool_name=step.get("tool_name"), status=step["status"], details=step.get("details", ""), timestamp=step.get("timestamp", ""), duration_ms=step.get("duration_ms", 0)))
        session.add(record)
        session.flush()
        return record.investigation_id


def _to_dict(record: Investigation) -> dict:
    return {
        "investigation_id": record.investigation_id,
        "created_at": record.created_at.isoformat() if isinstance(record.created_at, datetime) else str(record.created_at),
        "target": record.target,
        "input_type": record.input_type,
        "stored_content": record.submitted_content,
        "language": record.language,
        "planner": record.planner,
        "risk": json.loads(record.risk_json or "{}"),
        "report": json.loads(record.report_json or "{}"),
        "classification": json.loads(record.classification_json or "{}"),
        "evidence": [
            {"source": e.source, "source_key": e.source_key, "evidence_type": e.evidence_type, "target": e.target, "status": e.status, "result": e.result, "severity": e.severity, "details": json.loads(e.raw_response or "{}"), "checked_at": e.checked_at, "duration_ms": e.duration_ms}
            for e in record.evidence
        ],
        "timeline": [
            {"step_name": l.step_name, "tool_name": l.tool_name, "status": l.status, "details": l.details, "timestamp": l.timestamp, "duration_ms": l.duration_ms}
            for l in record.logs
        ],
    }


def get_investigation(investigation_id: int) -> dict | None:
    init_db()
    with session_scope() as session:
        record = session.get(Investigation, investigation_id)
        return _to_dict(record) if record else None


def list_investigations(limit: int = 100) -> list[dict]:
    init_db()
    with session_scope() as session:
        rows = session.execute(select(Investigation).order_by(Investigation.created_at.desc(), Investigation.investigation_id.desc()).limit(limit)).scalars().all()
        return [
            {"investigation_id": r.investigation_id, "created_at": r.created_at, "target": r.target, "input_type": r.input_type, "risk_score": r.risk_score, "risk_level": r.risk_level, "confidence": r.confidence, "status": r.status, "language": r.language}
            for r in rows
        ]


def delete_investigation(investigation_id: int) -> bool:
    init_db()
    with session_scope() as session:
        record = session.get(Investigation, investigation_id)
        if not record:
            return False
        session.delete(record)
        return True


def delete_all() -> int:
    init_db()
    with session_scope() as session:
        rows = session.execute(select(Investigation)).scalars().all()
        for r in rows:
            session.delete(r)
        return len(rows)


def statistics() -> dict:
    init_db()
    with session_scope() as session:
        total = session.execute(select(func.count(Investigation.investigation_id))).scalar() or 0
        by_level = dict(session.execute(select(Investigation.risk_level, func.count()).group_by(Investigation.risk_level)).all())
        by_type = dict(session.execute(select(Investigation.input_type, func.count()).group_by(Investigation.input_type)).all())
        by_status = dict(session.execute(select(Investigation.status, func.count()).group_by(Investigation.status)).all())
        avg_score = session.execute(select(func.avg(Investigation.risk_score))).scalar() or 0
        source_status = session.execute(select(EvidenceRecord.source, EvidenceRecord.status, func.count()).group_by(EvidenceRecord.source, EvidenceRecord.status)).all()
        return {"total": total, "by_level": by_level, "by_type": by_type, "by_status": by_status, "avg_score": round(float(avg_score), 1), "source_status": [tuple(r) for r in source_status]}
