"""Fail-closed completion gate for a managed Hunter run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError, MissingValidationError, VerificationError
from hunter_managed_scan.models.final_output import FinalOutput
from hunter_managed_scan.models.manifest import TargetSnapshot
from hunter_managed_scan.utilities.audit_log import AuditLog, aggregate_acu_usage
from hunter_managed_scan.utilities.acu_budget import acu_budget_snapshot
from hunter_managed_scan.utilities.cvss import calculate_base_score
from hunter_managed_scan.utilities.json_io import read_json, read_jsonl, write_json
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.target_guard import require_target_unchanged
from hunter_managed_scan.utilities.verify_validation_artifacts import has_executable_attempt


def _initial_snapshot(manifest: dict[str, Any]) -> TargetSnapshot:
    value = manifest["initial_target_snapshot"]
    return TargetSnapshot(str(value["commit_sha"]), str(value["status_porcelain"]), str(value["diff_sha256"]))


def _instance_identity(instance: dict[str, Any]) -> tuple[Any, ...]:
    return (
        instance["file"],
        instance["start_line"],
        instance["end_line"],
        instance["excerpt_sha256"],
        instance["endpoint_or_workflow"],
    )


def _load_verified_validations(run_dir: Path) -> list[dict[str, Any]]:
    receipts = [read_json(path) for path in sorted((run_dir / "validations").glob("*/verified-receipt.json"))]
    ids = [item.get("finding_id") for item in receipts]
    if len(ids) != len(set(ids)):
        raise MissingValidationError("a finding has more than one accepted validation result")
    for receipt in receipts:
        if receipt.get("verification_status") != "ACCEPTED" or not receipt.get("executable_attempt"):
            raise MissingValidationError("validation receipt is not accepted with an executable attempt")
        if not has_executable_attempt(receipt["validation_result"]):
            raise MissingValidationError("validation result lacks a meaningful executable attempt")
    return [item["validation_result"] for item in receipts]


def _verify_coverage(plan: dict[str, Any], final_coverage: dict[str, Any]) -> None:
    numbers = [int(item["class_number"]) for item in plan.get("entries", [])]
    if len(numbers) != 85 or set(numbers) != set(range(1, 86)):
        raise IncompleteCoverageError("coverage plan does not contain every taxonomy class exactly once")
    for entry in plan["entries"]:
        task_ids = list(entry.get("task_ids", []))
        if len(task_ids) != 2 or "coverage-auditor" not in task_ids or not any(
            task_id != "coverage-auditor" for task_id in task_ids
        ):
            raise IncompleteCoverageError(
                f"class {entry['class_number']} lacks both a domain investigator and coverage auditor owner"
            )
    final_numbers = [int(item["class_number"]) for item in final_coverage.get("entries", [])]
    if len(final_numbers) != 85 or set(final_numbers) != set(range(1, 86)):
        raise IncompleteCoverageError("final coverage ledger does not contain every class exactly once")
    if not final_coverage.get("summary", {}).get("complete"):
        raise IncompleteCoverageError("final coverage ledger contains unresolved coverage gaps")
    always = {item["class_number"] for item in plan["entries"] if item["preliminary_state"] == "ALWAYS_CHECK"}
    reviewed = {
        item["class_number"] for item in final_coverage["entries"] if item["final_state"] == "REVIEWED"
    }
    if not always.issubset(reviewed):
        raise IncompleteCoverageError("one or more always-check classes were not reviewed")


def _verify_packages(run_dir: Path, plan: dict[str, Any]) -> None:
    packages = [read_json(path) for path in sorted((run_dir / "work-packages").glob("*.json"))]
    package_ids = {item["task_id"] for item in packages}
    planned_ids = {task for entry in plan["entries"] for task in entry["task_ids"]}
    if package_ids != planned_ids:
        raise IncompleteCoverageError("a planned work package is missing or an unplanned package exists")
    for task_id in package_ids:
        if not (run_dir / "investigation" / "verified" / f"{task_id}.json").is_file():
            raise IncompleteCoverageError(f"accepted child result is missing for {task_id}")
    planned_targets = {
        item["target_id"] for entry in plan["entries"] for item in entry.get("logic_targets", [])
    }
    owned_targets = {item["target_id"] for package in packages for item in package.get("logic_targets", [])}
    if not planned_targets.issubset(owned_targets):
        raise IncompleteCoverageError("one or more logic targets have no work-package owner")
    planned_surfaces = {
        str(item["carrier_type"])
        for entry in plan["entries"]
        for item in entry.get("carrier_evidence", [])
        if item.get("carrier_type")
    }
    owned_surfaces = {surface for package in packages for surface in package.get("security_surfaces", [])}
    if not planned_surfaces.issubset(owned_surfaces):
        raise IncompleteCoverageError("one or more detected security surfaces have no assigned package")


def completion_gate(*, run_dir: Path, target_repo_path: Path) -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    plan = read_json(run_dir / "coverage" / "coverage-plan.json")
    final_coverage = read_json(run_dir / "coverage" / "coverage-final.json")
    _verify_coverage(plan, final_coverage)
    _verify_packages(run_dir, plan)

    normalized = read_json(run_dir / "investigation" / "normalized" / "findings.json")
    clustered = read_json(run_dir / "root-causes" / "findings-clustered.json")
    before_instances = {
        _instance_identity(instance) for finding in normalized for instance in finding["affected_instances"]
    }
    after_instances = {
        _instance_identity(instance) for finding in clustered for instance in finding["affected_instances"]
    }
    if not before_instances.issubset(after_instances):
        raise VerificationError("affected instances were lost during exact duplicate clustering")

    validations = _load_verified_validations(run_dir)
    clustered_ids = {item["finding_id"] for item in clustered}
    validation_ids = {item["finding_id"] for item in validations}
    if clustered_ids != validation_ids:
        raise MissingValidationError("every surviving verified finding must have exactly one validation result")

    critic = read_json(run_dir / "critic" / "critic-result.json")
    validate_artifact(critic, "critic-result.schema.json")
    critic_ids = [item["finding_id"] for item in critic["decisions"]]
    if len(critic_ids) != len(set(critic_ids)) or set(critic_ids) != clustered_ids:
        raise VerificationError("fresh-context Critic output must decide every finding exactly once")
    final_findings = read_json(run_dir / "critic" / "findings-reviewed.json")
    for finding in final_findings:
        score = calculate_base_score(str(finding["cvss_vector"]))
        if score != float(finding["cvss_score"]):
            raise VerificationError("final finding contains inconsistent CVSS arithmetic")

    require_target_unchanged(target_repo_path, Path(manifest["results_repo_path"]), _initial_snapshot(manifest))
    audit_records = read_jsonl(run_dir / "audit-log.jsonl")
    maximum_total_acu = float(manifest["budgets"]["maximum_total_acu"])
    budget_snapshot = acu_budget_snapshot(audit_records, maximum_total_acu)
    if any(item.get("event") == "GLOBAL_ACU_BUDGET_EXHAUSTED" for item in audit_records):
        raise IncompleteCoverageError("global ACU budget exhaustion left required work incomplete")
    if budget_snapshot["actual_acu"] > maximum_total_acu:
        raise IncompleteCoverageError("actual ACU usage exceeds the configured global run budget")
    status_counts: dict[str, int] = {"CONFIRMED": 0, "FALSE_POSITIVE": 0, "INCONCLUSIVE": 0}
    for result in validations:
        status_counts[result["validation_status"]] += 1
    verdict_counts: dict[str, int] = {"CONFIRMED": 0, "DOWNGRADED": 0, "REJECTED": 0}
    for decision in critic["decisions"]:
        verdict_counts[decision["verdict"]] += 1
    acu_usage = aggregate_acu_usage(audit_records)
    acu_usage.update(budget_snapshot)
    output = FinalOutput(
        run_id=manifest["run_id"],
        target_repository=manifest["target_repository"],
        target_commit=manifest["target_commit"],
        status="COMPLETE",
        findings=tuple(final_findings),
        coverage_summary=final_coverage["summary"],
        validation_summary={"finding_count": len(clustered), "status_counts": status_counts},
        critic_summary={"decision_count": len(critic["decisions"]), "verdict_counts": verdict_counts},
        acu_usage=acu_usage,
    ).as_dict()
    validate_artifact(output, "final-output.schema.json")
    write_json(run_dir / "findings-final.json", final_findings)
    write_json(run_dir / "final-output.json", output)
    (run_dir / "EXECUTIVE_BRIEF.md").write_text(
        "# Hunter Managed Scan Executive Brief\n\n"
        f"Run `{manifest['run_id']}` completed for `{manifest['target_repository']}` at "
        f"`{manifest['target_commit']}`. Final findings: {len(final_findings)}. "
        "Every surviving investigated candidate received one mechanically verified runtime-validation record "
        "and a fresh-context Critic decision.\n",
        encoding="utf-8",
    )
    (run_dir / "RUN_SUMMARY.md").write_text(
        "# Run Summary\n\n"
        f"- Status: COMPLETE\n- Coverage classes: 85\n- Coverage gaps: 0\n"
        f"- Verified candidates: {len(clustered)}\n- Final findings: {len(final_findings)}\n"
        f"- Total recorded ACUs: {output['acu_usage']['total_acu']}\n",
        encoding="utf-8",
    )
    for required in ("findings-final.json", "final-output.json", "EXECUTIVE_BRIEF.md", "RUN_SUMMARY.md"):
        if not (run_dir / required).is_file():
            raise VerificationError(f"completion artifact was not written: {required}")
    require_target_unchanged(target_repo_path, Path(manifest["results_repo_path"]), _initial_snapshot(manifest))
    AuditLog(run_dir / "audit-log.jsonl").append(
        "completion_gate",
        run_id=str(manifest["run_id"]),
        details={"status": "COMPLETE", "final_finding_count": len(final_findings)},
    )
    return output
