"""Canonical deterministic JSON Lines audit event construction."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunter_managed_scan.utilities.json_io import read_jsonl, write_jsonl


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(
        self,
        event: str,
        *,
        run_id: str,
        details: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        existing = read_jsonl(self.path) if self.path.exists() else []
        record = {
            "sequence": len(existing) + 1,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "event": event,
            "details": details or {},
        }
        write_jsonl(self.path, [*existing, record])
        return record


def aggregate_acu_usage(records: list[dict[str, Any]]) -> dict[str, Any]:
    latest_by_session: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []
    for record in records:
        if record.get("event") != "session_usage":
            continue
        session_id = str(record.get("details", {}).get("session_id", ""))
        if session_id:
            latest_by_session[session_id] = record
        else:
            unkeyed.append(record)
    usages = [*unkeyed, *latest_by_session.values()]
    parent = 0.0
    children: dict[str, float] = {}
    for record in usages:
        details = record.get("details", {})
        value = float(details.get("actual_acu", 0.0))
        session_id = str(details.get("session_id", "unknown"))
        if details.get("role") == "ORCHESTRATOR":
            parent += value
        else:
            children[session_id] = children.get(session_id, 0.0) + value
    return {
        "parent_acu": round(parent, 4),
        "child_acu_by_session": dict(sorted(children.items())),
        "child_acu_total": round(sum(children.values()), 4),
        "total_acu": round(parent + sum(children.values()), 4),
        "usage_records": len(usages),
    }
