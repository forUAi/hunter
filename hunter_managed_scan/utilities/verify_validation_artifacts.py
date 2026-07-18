"""Verify validator artifacts and executable-attempt evidence."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from hunter_managed_scan.errors import VerificationError
from hunter_managed_scan.models.manifest import TargetSnapshot
from hunter_managed_scan.utilities.json_io import read_json, read_jsonl, write_json
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.secret_detection import verify_no_plaintext_secrets
from hunter_managed_scan.utilities.target_guard import require_target_unchanged

REQUIRED_VALIDATION_FILES = (
    "validation-result.json",
    "reproduction.md",
    "commands.jsonl",
    "output.txt",
    "environment.json",
)


def _initial_snapshot(manifest: dict[str, Any]) -> TargetSnapshot:
    value = manifest["initial_target_snapshot"]
    return TargetSnapshot(str(value["commit_sha"]), str(value["status_porcelain"]), str(value["diff_sha256"]))


def has_executable_attempt(result: dict[str, Any]) -> bool:
    commands = result.get("commands")
    return bool(
        isinstance(commands, list)
        and any(isinstance(item, dict) and str(item.get("command", "")).strip() for item in commands)
        and result.get("reproduction_steps")
        and result.get("observed_outcome")
        and result.get("control_outcome")
    )


def validate_runtime_result(result: dict[str, Any]) -> None:
    """Validate schema and the non-negotiable runtime-proof contract."""

    validate_artifact(result, "validation-result.schema.json")
    if not has_executable_attempt(result):
        raise VerificationError("validation result has no meaningful executable attempt and control")
    if result["validation_status"] == "INCONCLUSIVE" and not (
        result["blocking_condition"]
        and result["missing_evidence"]
        and result["confirmation_criteria"]
        and result["limitations"]
    ):
        raise VerificationError(
            "INCONCLUSIVE validation requires a blocking condition, missing evidence, confirmation criteria, and limitations"
        )


def verify_validation_result(
    *,
    run_dir: Path,
    pack: dict[str, Any],
    finding_id: str,
    artifact_dir: Path,
    target_repo_path: Path,
    changed_paths: list[str] | None = None,
    write_receipt: bool = True,
) -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    for key, expected in {
        "run_id": manifest["run_id"],
        "target_repository": manifest["target_repository"],
        "target_commit": manifest["target_commit"],
    }.items():
        if pack.get(key) != expected:
            raise VerificationError(f"validation pack has wrong {key}")
    if finding_id not in pack["finding_ids"]:
        raise VerificationError("validation result is outside its assigned pack")
    expected_suffix = ("scan_runs", manifest["run_id"], "validations", finding_id)
    resolved = artifact_dir.resolve(strict=True)
    if tuple(resolved.parts[-len(expected_suffix) :]) != expected_suffix:
        raise VerificationError("validation artifact directory does not match its assigned finding path")
    allowed_roots = [
        PurePosixPath("scan_runs") / str(manifest["run_id"]) / "validations" / str(assigned_id)
        for assigned_id in pack["finding_ids"]
    ]
    for path in changed_paths or []:
        candidate = PurePosixPath(path)
        if candidate.is_absolute() or ".." in candidate.parts or not any(
            candidate == allowed or allowed in candidate.parents for allowed in allowed_roots
        ):
            raise VerificationError(f"validator wrote outside its allowed result path: {path}")
    for name in REQUIRED_VALIDATION_FILES:
        if not (resolved / name).is_file():
            raise VerificationError(f"validation result is missing {name}")
    result = read_json(resolved / "validation-result.json")
    validate_runtime_result(result)
    if result["finding_id"] != finding_id or result["target_commit"] != manifest["target_commit"]:
        raise VerificationError("validation result identity does not match the finding or target commit")
    commands = read_jsonl(resolved / "commands.jsonl")
    environment = read_json(resolved / "environment.json")
    reproduction = (resolved / "reproduction.md").read_text(encoding="utf-8")
    output = (resolved / "output.txt").read_text(encoding="utf-8")
    if commands != result["commands"]:
        raise VerificationError("commands.jsonl does not exactly match validation-result commands")
    if environment != result["environment"]:
        raise VerificationError("environment.json does not exactly match the validation-result environment")
    if not reproduction.strip() or not output.strip():
        raise VerificationError("runtime validation reproduction and output artifacts must be non-empty")
    for relative in result["artifacts"]:
        artifact = PurePosixPath(relative)
        if artifact.is_absolute() or ".." in artifact.parts:
            raise VerificationError(f"validation result contains an unsafe artifact path: {relative}")
        candidate = resolved / Path(*artifact.parts)
        if not candidate.is_file():
            raise VerificationError(f"validation result references a missing artifact: {relative}")
    verify_no_plaintext_secrets(
        {
            "result": result,
            "commands": commands,
            "environment": environment,
            "reproduction": reproduction,
            "output": output,
        }
    )
    artifacts_root = resolved / "artifacts"
    if artifacts_root.is_dir():
        for candidate in sorted(path for path in artifacts_root.rglob("*") if path.is_file()):
            try:
                if candidate.stat().st_size <= 2_000_000:
                    verify_no_plaintext_secrets(candidate.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                continue
    require_target_unchanged(target_repo_path, Path(manifest["results_repo_path"]), _initial_snapshot(manifest))
    receipt = {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "pack_id": pack["pack_id"],
        "finding_id": finding_id,
        "target_commit": manifest["target_commit"],
        "verification_status": "ACCEPTED",
        "executable_attempt": True,
        "validation_result": result,
    }
    if write_receipt:
        write_json(run_dir / "validations" / finding_id / "verified-receipt.json", receipt)
        AuditLog(run_dir / "audit-log.jsonl").append(
            "validation_verified",
            run_id=str(manifest["run_id"]),
            details={
                "pack_id": pack["pack_id"],
                "finding_id": finding_id,
                "validation_status": result["validation_status"],
            },
        )
    return receipt
