"""Create an immutable managed-scan run and deterministic work plan."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunter_managed_scan.adapters import _accelerator  # noqa: F401
from hunter_managed_scan.adapters._accelerator import CANONICAL_TAXONOMY
from hunter_managed_scan.adapters.inventory_adapter import load_preparation_bundle, run_deterministic_preparation
from hunter_accelerator.taxonomy import load_and_validate_taxonomy

from hunter_managed_scan.errors import OperationalError
from hunter_managed_scan.models.manifest import BudgetConfiguration, RunManifest
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.create_coverage_plan import create_coverage_plan
from hunter_managed_scan.utilities.create_work_packages import create_work_packages
from hunter_managed_scan.utilities.json_io import write_json
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.target_guard import require_initial_target, require_target_unchanged

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RUN_DIRECTORIES = (
    "inventory",
    "coverage",
    "work-packages",
    "investigation/raw",
    "investigation/normalized",
    "investigation/verified",
    "root-causes",
    "validation-packs",
    "validations",
    "critic",
)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _current_branch(repository: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "branch", "--show-current"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OperationalError("results repository Git branch could not be inspected") from exc
    branch = completed.stdout.strip()
    if completed.returncode != 0 or not branch:
        raise OperationalError("results repository must be on a named Git branch")
    return branch


def prepare_run(
    *,
    target_repo_path: Path,
    target_repository: str,
    target_commit: str,
    results_repo_path: Path,
    results_branch: str,
    run_id: str,
    taxonomy_file: Path = CANONICAL_TAXONOMY,
    budgets: BudgetConfiguration | None = None,
    created_at: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise OperationalError("run ID must contain only letters, numbers, dot, underscore, and dash")
    selected_budgets = budgets or BudgetConfiguration()
    budget_values = selected_budgets.as_dict()
    if any(int(budget_values[key]) < 1 for key in (
        "parent_orchestrator_acu", "investigator_child_acu", "coverage_auditor_acu",
        "validator_pack_acu", "critic_acu", "maximum_investigation_children", "maximum_validation_children",
    )):
        raise OperationalError("ACU and child-count budgets must be positive")
    if selected_budgets.maximum_investigation_children > 7 or selected_budgets.maximum_validation_children > 5:
        raise OperationalError("configured child count exceeds the managed-scan safety maximum")
    if not 0 <= selected_budgets.maximum_retry_count <= 2:
        raise OperationalError("maximum retry count must be between zero and two")
    try:
        target = target_repo_path.expanduser().resolve(strict=True)
        results = results_repo_path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise OperationalError("target and results repository paths must exist") from exc
    if not target.is_dir() or not results.is_dir():
        raise OperationalError("target and results repository paths must be directories")
    if target == results or _is_within(results, target) or _is_within(target, results):
        raise OperationalError("target and results repositories must be separate filesystem trees")
    if _current_branch(results) != results_branch:
        raise OperationalError("results repository current branch does not match --results-branch")
    taxonomy = load_and_validate_taxonomy(taxonomy_file)
    run_dir = results / "scan_runs" / run_id
    if run_dir.exists():
        raise OperationalError(f"run directory already exists: {run_dir}")
    initial = require_initial_target(target, results, target_commit)
    for relative in RUN_DIRECTORIES:
        (run_dir / relative).mkdir(parents=True, exist_ok=False)

    accelerator_output = run_dir / "inventory" / "accelerator"
    accelerator_status, _pipeline_result = run_deterministic_preparation(
        target,
        accelerator_output,
        results / ".hunter-managed-cache",
        taxonomy.source_path,
    )
    if accelerator_status not in {"COMPLETE", "PARTIAL"}:
        raise OperationalError("deterministic preparation failed")
    require_target_unchanged(target, results, initial)
    preparation = load_preparation_bundle(accelerator_output)
    plan = create_coverage_plan(
        run_id=run_id,
        target_repository=target_repository,
        target_commit=target_commit,
        taxonomy=taxonomy,
        preparation=preparation,
    )
    packages = create_work_packages(plan=plan, preparation=preparation, budgets=selected_budgets)
    manifest = RunManifest(
        run_id=run_id,
        target_repository=target_repository,
        target_repo_path=str(target),
        target_commit=target_commit,
        results_repo_path=str(results),
        results_branch=results_branch,
        taxonomy_file=str(taxonomy.source_path),
        taxonomy_version=taxonomy.version,
        accelerator_status=accelerator_status,
        created_at=created_at or datetime.now(timezone.utc).isoformat(),
        initial_target_snapshot=initial,
        budgets=selected_budgets,
    )
    manifest_value = manifest.as_dict()
    plan_value = plan.as_dict()
    validate_artifact(manifest_value, "run-manifest.schema.json")
    validate_artifact(plan_value, "coverage-plan.schema.json")
    write_json(run_dir / "run-manifest.json", manifest_value)
    write_json(run_dir / "coverage" / "coverage-plan.json", plan_value)
    for package in packages:
        value = package.as_dict()
        validate_artifact(value, "work-package.schema.json")
        write_json(run_dir / "work-packages" / f"{package.task_id}.json", value)

    audit = AuditLog(run_dir / "audit-log.jsonl")
    timestamp = manifest.created_at
    audit.append("run_created", run_id=run_id, timestamp=timestamp, details={"results_branch": results_branch})
    audit.append(
        "target_snapshot",
        run_id=run_id,
        timestamp=timestamp,
        details={"target_repository": target_repository, "target_commit": target_commit},
    )
    audit.append(
        "deterministic_preparation",
        run_id=run_id,
        timestamp=timestamp,
        details={"status": accelerator_status, "telemetry": preparation["telemetry"]},
    )
    audit.append(
        "coverage_plan_created",
        run_id=run_id,
        timestamp=timestamp,
        details={"class_count": len(plan.entries)},
    )
    audit.append(
        "work_packages_created",
        run_id=run_id,
        timestamp=timestamp,
        details={"task_ids": [package.task_id for package in packages]},
    )
    audit.append("target_immutability_verified", run_id=run_id, timestamp=timestamp)
    return run_dir, {
        "manifest": manifest_value,
        "coverage_plan": plan_value,
        "work_packages": [package.as_dict() for package in packages],
        "accelerator_status": accelerator_status,
    }
