"""Strict parent-side verification for investigator child branch artifacts."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from hunter_managed_scan.adapters import _accelerator  # noqa: F401
from hunter_accelerator.hashing import stable_json_hash
from hunter_accelerator.taxonomy import load_and_validate_taxonomy

from hunter_managed_scan.errors import VerificationError
from hunter_managed_scan.models.manifest import TargetSnapshot
from hunter_managed_scan.utilities.json_io import read_json, read_jsonl, write_json
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.secret_detection import verify_no_plaintext_secrets
from hunter_managed_scan.utilities.target_guard import require_target_unchanged
from hunter_managed_scan.utilities.verify_excerpts import verify_finding_excerpts

REQUIRED_CHILD_FILES = ("manifest.json", "coverage.json", "findings.json", "evidence.jsonl", "result.json")
REVIEW_STATUSES = frozenset({"REVIEWED_NO_FINDING", "CANDIDATE_PRODUCED", "ABSTAINED", "COVERAGE_GAP"})


def _expected_suffix(run_id: str, task_id: str) -> tuple[str, ...]:
    return ("scan_runs", run_id, "tasks", task_id)


def _has_suffix(path: Path, suffix: tuple[str, ...]) -> bool:
    return len(path.parts) >= len(suffix) and tuple(path.parts[-len(suffix) :]) == suffix


def _verify_changed_paths(changed_paths: list[str], run_id: str, task_id: str) -> None:
    allowed = PurePosixPath("scan_runs") / run_id / "tasks" / task_id
    for value in changed_paths:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or path != allowed and allowed not in path.parents:
            raise VerificationError(f"child wrote outside its allowed result path: {value}")


def _initial_snapshot(manifest: dict[str, Any]) -> TargetSnapshot:
    value = manifest["initial_target_snapshot"]
    return TargetSnapshot(
        commit_sha=str(value["commit_sha"]),
        status_porcelain=str(value["status_porcelain"]),
        diff_sha256=str(value["diff_sha256"]),
    )


def verify_child_task(
    *,
    run_dir: Path,
    work_package: dict[str, Any],
    child_artifact_dir: Path,
    target_repo_path: Path,
    changed_paths: list[str],
    write_receipt: bool = True,
) -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    run_id = str(manifest["run_id"])
    task_id = str(work_package["task_id"])
    resolved_child = child_artifact_dir.resolve(strict=True)
    if not _has_suffix(resolved_child, _expected_suffix(run_id, task_id)):
        raise VerificationError("child artifact directory does not match the assigned run/task path")
    _verify_changed_paths(changed_paths, run_id, task_id)
    for name in REQUIRED_CHILD_FILES:
        if not (resolved_child / name).is_file():
            raise VerificationError(f"child result is missing {name}")
    child_manifest = read_json(resolved_child / "manifest.json")
    result = read_json(resolved_child / "result.json")
    coverage = read_json(resolved_child / "coverage.json")
    findings = read_json(resolved_child / "findings.json")
    evidence = read_jsonl(resolved_child / "evidence.jsonl")
    validate_artifact(child_manifest, "child-task-manifest.schema.json")
    validate_artifact(result, "investigation-result.schema.json")
    validate_artifact(coverage, "investigation-coverage.schema.json")
    expected_identity = {
        "run_id": run_id,
        "task_id": task_id,
        "target_repository": manifest["target_repository"],
        "target_commit": manifest["target_commit"],
    }
    for key, expected in expected_identity.items():
        if result.get(key) != expected or child_manifest.get(key) != expected:
            raise VerificationError(f"child artifact has wrong {key}: expected {expected}")
    if child_manifest.get("result_branch") != work_package["result_branch"]:
        raise VerificationError("child manifest has the wrong result branch")
    if result["status"] == "INCOMPLETE":
        raise VerificationError("child result is incomplete and must be retried or escalated")
    if not isinstance(coverage, list):
        raise VerificationError("child coverage artifact must be a list")
    coverage_numbers: list[int] = []
    coverage_by_number: dict[int, dict[str, Any]] = {}
    for item in coverage:
        if not isinstance(item, dict) or item.get("review_status") not in REVIEW_STATUSES:
            raise VerificationError("child coverage contains an invalid review status")
        number = int(item.get("class_number", 0))
        coverage_numbers.append(number)
        coverage_by_number[number] = item
    expected_classes = sorted(int(value) for value in work_package["assigned_classes"])
    if sorted(coverage_numbers) != expected_classes or len(coverage_numbers) != len(set(coverage_numbers)):
        raise VerificationError("child coverage does not account for every assigned class exactly once")
    coverage_plan = read_json(run_dir / "coverage" / "coverage-plan.json")
    preliminary_by_number = {
        int(item["class_number"]): item["preliminary_state"] for item in coverage_plan["entries"]
    }
    for number, item in coverage_by_number.items():
        if preliminary_by_number[number] == "NEGATIVE_EVIDENCE_REVIEW" and not (
            item.get("fallback_searches") and item.get("reviewed_artifacts")
        ):
            raise VerificationError(
                f"negative-evidence class {number} lacks bounded fallback searches or reviewed inventory artifacts"
            )
    if not isinstance(findings, list):
        raise VerificationError("child findings artifact must be a list")
    inventory_path = run_dir / "inventory" / "accelerator" / "file-inventory.jsonl"
    inventory = {item["relative_path"]: item for item in read_jsonl(inventory_path)}
    taxonomy = load_and_validate_taxonomy(Path(manifest["taxonomy_file"]))
    taxonomy_by_number = {int(item["class_number"]): item for item in taxonomy.classes}
    finding_classes: set[int] = set()
    for finding in findings:
        validate_artifact(finding, "finding.schema.json")
        if int(finding["class_number"]) not in expected_classes:
            raise VerificationError("child finding is outside its assigned classes")
        taxonomy_class = taxonomy_by_number[int(finding["class_number"])]
        for key, expected in {
            "class_name": taxonomy_class["class_name"],
            "category": taxonomy_class["family"],
            "owasp": taxonomy_class["owasp"],
        }.items():
            if finding[key] != expected:
                raise VerificationError(
                    f"finding {finding['finding_id']} has wrong authoritative {key} mapping"
                )
        finding_classes.add(int(finding["class_number"]))
        if finding["target_commit"] != manifest["target_commit"]:
            raise VerificationError("child finding cites the wrong target commit")
        verify_finding_excerpts(target_repo_path, finding)
        for instance in finding["affected_instances"]:
            record = inventory.get(instance["file"])
            if record and (record.get("generated") or record.get("test")) and not instance.get("production_relevance"):
                raise VerificationError("generated or test evidence lacks an explicit production reachability argument")
        verify_no_plaintext_secrets(finding)
    candidate_classes = {
        number for number, item in coverage_by_number.items() if item["review_status"] == "CANDIDATE_PRODUCED"
    }
    if candidate_classes != finding_classes:
        raise VerificationError(
            "CANDIDATE_PRODUCED coverage outcomes must exactly match classes with candidate findings"
        )
    verify_no_plaintext_secrets({"manifest": child_manifest, "coverage": coverage, "evidence": evidence, "result": result})
    require_target_unchanged(target_repo_path, Path(manifest["results_repo_path"]), _initial_snapshot(manifest))
    receipt = {
        "schema_version": 1,
        "run_id": run_id,
        "task_id": task_id,
        "target_commit": manifest["target_commit"],
        "verification_status": "ACCEPTED",
        "finding_count": len(findings),
        "coverage_class_count": len(coverage_numbers),
        "artifact_hash": stable_json_hash(
            {"manifest": child_manifest, "coverage": coverage, "findings": findings, "evidence": evidence, "result": result}
        ),
        "findings": findings,
        "coverage": coverage,
    }
    if write_receipt:
        write_json(run_dir / "investigation" / "verified" / f"{task_id}.json", receipt)
        AuditLog(run_dir / "audit-log.jsonl").append(
            "child_artifact_verified",
            run_id=run_id,
            details={
                "task_id": task_id,
                "result_branch": work_package["result_branch"],
                "verification_result": "ACCEPTED",
                "finding_count": len(findings),
            },
        )
    return receipt
