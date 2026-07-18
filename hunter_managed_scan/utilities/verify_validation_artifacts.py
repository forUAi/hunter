"""Verify validator artifacts and executable-attempt evidence."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
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
    try:
        _validate_command_relationships(result)
        return True
    except (VerificationError, KeyError, TypeError, ValueError):
        return False


COMMAND_REFERENCE = re.compile(r"\bcommand:([A-Za-z0-9][A-Za-z0-9._-]*)\b")


def _validate_command_relationships(result: dict[str, Any]) -> None:
    commands = result.get("commands")
    if not isinstance(commands, list) or not commands:
        raise VerificationError("validation result contains no command records")
    command_by_id: dict[str, dict[str, Any]] = {}
    for command in commands:
        command_id = str(command.get("command_id", ""))
        if not command_id or command_id in command_by_id:
            raise VerificationError("validation command IDs must be present and unique")
        command_by_id[command_id] = command
        try:
            started = datetime.fromisoformat(str(command["started_at"]).replace("Z", "+00:00"))
            finished = datetime.fromisoformat(str(command["finished_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as exc:
            raise VerificationError(f"command {command_id} has invalid timestamps") from exc
        try:
            if finished < started:
                raise VerificationError(f"command {command_id} finished before it started")
        except TypeError as exc:
            raise VerificationError(f"command {command_id} timestamps use inconsistent time zones") from exc
    tests = {key: value for key, value in command_by_id.items() if value.get("is_control") is False}
    controls = {key: value for key, value in command_by_id.items() if value.get("is_control") is True}
    if not tests:
        raise VerificationError("validation requires at least one test command")
    if not controls:
        raise VerificationError("validation requires at least one explicit control command")
    controlled_tests: set[str] = set()
    for command_id, control in controls.items():
        target = control.get("control_for_command_id")
        if target not in tests:
            raise VerificationError(f"control command {command_id} does not reference a valid test command")
        test = tests[str(target)]
        if str(control["command"]).strip() == str(test["command"]).strip():
            raise VerificationError("test and control commands cannot be identical unsupported claims")
        if str(control["purpose"]).strip() == str(test["purpose"]).strip():
            raise VerificationError("test and control purposes must describe distinct claims")
        controlled_tests.add(str(target))
    if set(tests) != controlled_tests:
        raise VerificationError("every test command must have an explicit control relationship")
    if any(command.get("control_for_command_id") is not None for command in tests.values()):
        raise VerificationError("test commands cannot point to another command as a control")
    referenced: set[str] = set()
    for step in result.get("reproduction_steps", []):
        ids = set(COMMAND_REFERENCE.findall(str(step)))
        if not ids:
            raise VerificationError("every reproduction step must reference a command ID")
        unknown = ids - set(command_by_id)
        if unknown:
            raise VerificationError(f"reproduction references unknown command ID: {sorted(unknown)[0]}")
        referenced.update(ids)
    if not set(command_by_id).issubset(referenced):
        raise VerificationError("reproduction steps must reference every executed command ID")
    observed_ids = set(COMMAND_REFERENCE.findall(str(result.get("observed_outcome", ""))))
    control_ids = set(COMMAND_REFERENCE.findall(str(result.get("control_outcome", ""))))
    if not observed_ids.intersection(tests):
        raise VerificationError("observed outcome must reference a test command ID")
    if not control_ids.intersection(controls):
        raise VerificationError("control outcome must reference a control command ID")


def verify_command_outputs(result: dict[str, Any], artifact_dir: Path) -> None:
    output_root = artifact_dir / "command-output"
    expected_paths: set[Path] = set()
    for command in result["commands"]:
        command_id = str(command["command_id"])
        for stream in ("stdout", "stderr"):
            path = output_root / f"{command_id}.{stream}"
            expected_paths.add(path)
            if not path.is_file():
                raise VerificationError(f"command {command_id} is missing stored {stream}")
            payload = path.read_bytes()
            try:
                sanitized_text = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise VerificationError(f"command {command_id} {stream} must be sanitized UTF-8 text") from exc
            verify_no_plaintext_secrets(sanitized_text)
            digest = hashlib.sha256(payload).hexdigest()
            if digest != command[f"{stream}_sha256"]:
                raise VerificationError(f"command {command_id} has a fabricated or mismatched {stream} hash")
    actual_paths = {path for path in output_root.glob("*") if path.is_file()} if output_root.is_dir() else set()
    if actual_paths != expected_paths:
        raise VerificationError("command output contains a file not tied to a command record")


def validate_runtime_result(result: dict[str, Any]) -> None:
    """Validate schema and the non-negotiable runtime-proof contract."""

    validate_artifact(result, "validation-result.schema.json")
    _validate_command_relationships(result)
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
    hash_by_path = {item["path"]: item["sha256"] for item in result["artifact_hashes"]}
    if len(hash_by_path) != len(result["artifact_hashes"]) or set(hash_by_path) != set(result["artifacts"]):
        raise VerificationError("every validation artifact must have exactly one recorded SHA-256 hash")
    for relative in result["artifacts"]:
        candidate = resolved / Path(*PurePosixPath(relative).parts)
        payload = candidate.read_bytes()
        try:
            verify_no_plaintext_secrets(payload.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        if hashlib.sha256(payload).hexdigest() != hash_by_path[relative]:
            raise VerificationError(f"validation artifact hash does not match: {relative}")
    verify_command_outputs(result, resolved)
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
