"""Fail-closed global ACU accounting and child-launch authorization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError, OperationalError
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.json_io import read_jsonl


def maximum_possible_acu(budgets: dict[str, Any]) -> dict[str, float]:
    attempts = int(budgets["maximum_retry_count"]) + 1
    investigation_children = int(budgets["maximum_investigation_children"])
    investigation_per_attempt = (
        max(0, investigation_children - 1) * float(budgets["investigator_child_acu"])
        + (float(budgets["coverage_auditor_acu"]) if investigation_children else 0.0)
    )
    validation_per_attempt = (
        int(budgets["maximum_validation_children"]) * float(budgets["validator_pack_acu"])
    )
    critic_per_attempt = float(budgets["critic_acu"])
    uncapped = float(budgets["parent_orchestrator_acu"]) + attempts * (
        investigation_per_attempt + validation_per_attempt + critic_per_attempt
    )
    cap = float(budgets["maximum_total_acu"])
    return {
        "uncapped_maximum_acu": round(uncapped, 4),
        "global_cap_acu": round(cap, 4),
        "effective_maximum_acu": round(min(uncapped, cap), 4),
    }


def _attempt_key(details: dict[str, Any]) -> tuple[str, int]:
    return (str(details.get("task_id", "")), int(details.get("retry_number", 0)))


def _latest_usage_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []
    for item in records:
        if item.get("event") != "session_usage":
            continue
        session_id = str(item.get("details", {}).get("session_id", ""))
        if session_id:
            latest[session_id] = item
        else:
            unkeyed.append(item)
    return [*unkeyed, *latest.values()]


def acu_budget_snapshot(records: list[dict[str, Any]], maximum_total_acu: float) -> dict[str, Any]:
    launches = [item for item in records if item.get("event") == "child_launch_authorized"]
    usages = _latest_usage_records(records)
    configurations = [item for item in records if item.get("event") == "acu_budget_configured"]
    configured_parent = (
        float(configurations[-1].get("details", {}).get("parent_orchestrator_acu", 0.0))
        if configurations
        else 0.0
    )
    actual = sum(float(item.get("details", {}).get("actual_acu", 0.0)) for item in usages)
    settled_attempts = {
        _attempt_key(item.get("details", {})) for item in usages if item.get("details", {}).get("task_id")
    }
    outstanding = sum(
        float(item.get("details", {}).get("maximum_acu", 0.0))
        for item in launches
        if _attempt_key(item.get("details", {})) not in settled_attempts
    )
    planned_children = sum(float(item.get("details", {}).get("maximum_acu", 0.0)) for item in launches)
    planned = configured_parent + planned_children
    planned_by_phase: dict[str, float] = {"PARENT": configured_parent} if configured_parent else {}
    planned_by_role: dict[str, float] = {"ORCHESTRATOR": configured_parent} if configured_parent else {}
    for item in launches:
        details = item.get("details", {})
        value = float(details.get("maximum_acu", 0.0))
        phase = str(details.get("phase", "UNSPECIFIED"))
        role = str(details.get("role", "UNSPECIFIED"))
        planned_by_phase[phase] = planned_by_phase.get(phase, 0.0) + value
        planned_by_role[role] = planned_by_role.get(role, 0.0) + value
    by_phase: dict[str, float] = {}
    by_role: dict[str, float] = {}
    retry_acu = 0.0
    for item in usages:
        details = item.get("details", {})
        value = float(details.get("actual_acu", 0.0))
        phase = str(details.get("phase", "UNSPECIFIED"))
        role = str(details.get("role", "UNSPECIFIED"))
        by_phase[phase] = by_phase.get(phase, 0.0) + value
        by_role[role] = by_role.get(role, 0.0) + value
        if int(details.get("retry_number", 0)) > 0:
            retry_acu += value
    return {
        "maximum_total_acu": maximum_total_acu,
        "planned_maximum_acu": round(planned, 4),
        "planned_child_maximum_acu": round(planned_children, 4),
        "configured_parent_maximum_acu": round(configured_parent, 4),
        "planned_maximum_acu_by_phase": dict(
            sorted((key, round(value, 4)) for key, value in planned_by_phase.items())
        ),
        "planned_maximum_acu_by_role": dict(
            sorted((key, round(value, 4)) for key, value in planned_by_role.items())
        ),
        "actual_acu": round(actual, 4),
        "outstanding_reserved_acu": round(outstanding, 4),
        "remaining_acu": round(maximum_total_acu - actual, 4),
        "available_for_new_launch_acu": round(maximum_total_acu - actual - outstanding, 4),
        "actual_acu_by_phase": dict(sorted((key, round(value, 4)) for key, value in by_phase.items())),
        "actual_acu_by_role": dict(sorted((key, round(value, 4)) for key, value in by_role.items())),
        "retry_acu": round(retry_acu, 4),
    }


def authorize_child_launch(
    *,
    audit_path: Path,
    run_id: str,
    maximum_total_acu: float,
    task_id: str,
    role: str,
    phase: str,
    proposed_maximum_acu: float,
    retry_number: int = 0,
    verification_error: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    if maximum_total_acu <= 0 or proposed_maximum_acu <= 0:
        raise OperationalError("global and proposed child ACU budgets must be positive")
    if retry_number < 0:
        raise OperationalError("retry number cannot be negative")
    if retry_number > 0 and not verification_error:
        raise OperationalError("a retry requires the exact mechanical verification error")
    if retry_number == 0 and verification_error:
        raise OperationalError("an initial child launch cannot include a retry verification error")
    records = read_jsonl(audit_path) if audit_path.exists() else []
    attempt = (task_id, retry_number)
    if any(
        item.get("event") == "child_launch_authorized"
        and _attempt_key(item.get("details", {})) == attempt
        for item in records
    ):
        raise OperationalError(f"child attempt is already authorized: {task_id} retry {retry_number}")
    snapshot = acu_budget_snapshot(records, maximum_total_acu)
    projected = snapshot["actual_acu"] + snapshot["outstanding_reserved_acu"] + proposed_maximum_acu
    audit = AuditLog(audit_path)
    details = {
        "task_id": task_id,
        "role": role,
        "phase": phase,
        "retry_number": retry_number,
        "maximum_acu": proposed_maximum_acu,
        "actual_acu_already_consumed": snapshot["actual_acu"],
        "outstanding_reserved_acu": snapshot["outstanding_reserved_acu"],
        "projected_acu": round(projected, 4),
        "maximum_total_acu": maximum_total_acu,
        "verification_error": verification_error,
    }
    if projected > maximum_total_acu:
        details["incomplete_task"] = task_id
        audit.append(
            "GLOBAL_ACU_BUDGET_EXHAUSTED",
            run_id=run_id,
            details=details,
            timestamp=timestamp,
        )
        raise IncompleteCoverageError(
            f"GLOBAL_ACU_BUDGET_EXHAUSTED: cannot launch {task_id}; projected {projected:g} exceeds {maximum_total_acu:g}"
        )
    audit.append("child_launch_authorized", run_id=run_id, details=details, timestamp=timestamp)
    return acu_budget_snapshot(read_jsonl(audit_path), maximum_total_acu)
