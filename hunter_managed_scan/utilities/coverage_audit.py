"""Verify the independent coverage-auditor result against the 85-class plan."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError, VerificationError
from hunter_managed_scan.utilities.json_io import read_json, write_json
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.schema_validation import validate_artifact


def audit_from_verified_receipt(plan: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """Mechanically translate accepted auditor coverage into the final audit contract."""

    if receipt.get("verification_status") != "ACCEPTED" or receipt.get("task_id") != "coverage-auditor":
        raise VerificationError("coverage audit input is not an accepted coverage-auditor receipt")
    coverage = receipt.get("coverage")
    if not isinstance(coverage, list):
        raise VerificationError("coverage-auditor receipt does not contain child coverage")
    planned = {int(item["class_number"]): item for item in plan["entries"]}
    entries: list[dict[str, Any]] = []
    for item in coverage:
        number = int(item.get("class_number", 0))
        if number not in planned:
            raise VerificationError(f"coverage auditor returned an unplanned class: {number}")
        status = item.get("review_status")
        preliminary = planned[number]["preliminary_state"]
        gap = status in {"ABSTAINED", "COVERAGE_GAP"}
        if gap:
            final_state = "UNRESOLVED"
        elif status == "CANDIDATE_PRODUCED":
            final_state = "REVIEWED"
        elif preliminary == "NEGATIVE_EVIDENCE_REVIEW":
            final_state = "NEGATIVE_EVIDENCE_ACCEPTED"
        elif preliminary == "DOWNSTREAM_CHAIN_REVIEW":
            final_state = "DOWNSTREAM_CHAIN_REVIEW"
        else:
            final_state = "REVIEWED"
        entries.append(
            {
                "class_number": number,
                "final_state": final_state,
                "reviewed_by": "coverage-auditor",
                "notes": str(item.get("notes") or f"Coverage auditor recorded {status}."),
                "coverage_gap": gap,
            }
        )
    return {
        "schema_version": 1,
        "run_id": plan["run_id"],
        "target_repository": plan["target_repository"],
        "target_commit": plan["target_commit"],
        "produced_by": "coverage-auditor",
        "entries": sorted(entries, key=lambda value: value["class_number"]),
    }


def apply_coverage_audit(plan: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    validate_artifact(plan, "coverage-plan.schema.json")
    validate_artifact(audit, "coverage-audit.schema.json")
    for key in ("run_id", "target_repository", "target_commit"):
        if audit.get(key) != plan.get(key):
            raise VerificationError(f"coverage audit has wrong {key}")
    expected = {int(item["class_number"]): item for item in plan["entries"]}
    actual_numbers = [int(item["class_number"]) for item in audit["entries"]]
    if len(actual_numbers) != len(set(actual_numbers)) or set(actual_numbers) != set(expected):
        raise IncompleteCoverageError("coverage audit must account for all 85 planned classes exactly once")
    entries = sorted(audit["entries"], key=lambda item: item["class_number"])
    for entry in entries:
        planned = expected[int(entry["class_number"])]
        if planned["preliminary_state"] == "ALWAYS_CHECK" and entry["final_state"] != "REVIEWED":
            entry["coverage_gap"] = True
            entry["notes"] += "; always-check class was not reviewed"
    gaps = [item for item in entries if item["coverage_gap"] or item["final_state"] == "UNRESOLVED"]
    return {
        "schema_version": 1,
        "run_id": audit["run_id"],
        "target_repository": audit["target_repository"],
        "target_commit": audit["target_commit"],
        "produced_by": audit["produced_by"],
        "entries": entries,
        "summary": {"class_count": len(entries), "coverage_gap_count": len(gaps), "complete": not gaps},
    }


def coverage_audit_run(run_dir: Path, audit_path: Path) -> dict[str, Any]:
    plan = read_json(run_dir / "coverage" / "coverage-plan.json")
    supplied = read_json(audit_path)
    audit = (
        audit_from_verified_receipt(plan, supplied)
        if supplied.get("verification_status") == "ACCEPTED"
        else supplied
    )
    result = apply_coverage_audit(plan, audit)
    write_json(run_dir / "coverage" / "coverage-audit.json", audit)
    write_json(run_dir / "coverage" / "coverage-final.json", result)
    AuditLog(run_dir / "audit-log.jsonl").append(
        "coverage_audit",
        run_id=str(plan["run_id"]),
        details={
            "class_count": result["summary"]["class_count"],
            "coverage_gap_count": result["summary"]["coverage_gap_count"],
        },
    )
    if not result["summary"]["complete"]:
        raise IncompleteCoverageError(
            f"coverage audit reported {result['summary']['coverage_gap_count']} unresolved coverage gaps"
        )
    return result
