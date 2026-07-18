"""Command line interface for deterministic managed-session preparation and gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from hunter_managed_scan.adapters._accelerator import CANONICAL_TAXONOMY
from hunter_managed_scan.errors import ManagedScanError, OperationalError
from hunter_managed_scan.models.manifest import BudgetConfiguration
from hunter_managed_scan.utilities.apply_critic_results import apply_critic_results
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.cluster_root_causes import cluster_run_findings
from hunter_managed_scan.utilities.completion_gate import completion_gate
from hunter_managed_scan.utilities.coverage_audit import coverage_audit_run
from hunter_managed_scan.utilities.create_validation_packs import create_validation_packs
from hunter_managed_scan.utilities.json_io import read_json, write_json
from hunter_managed_scan.utilities.normalize_findings import normalize_run_findings
from hunter_managed_scan.utilities.prepare_run import prepare_run
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.verify_child_artifacts import verify_child_task
from hunter_managed_scan.utilities.verify_validation_artifacts import verify_validation_result


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m hunter_managed_scan.cli")
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="create deterministic inventory, coverage, and work packages")
    prepare.add_argument("--target-repo-path", type=_path, required=True)
    prepare.add_argument("--target-repo", required=True)
    prepare.add_argument("--target-commit", required=True)
    prepare.add_argument("--results-repo-path", type=_path, required=True)
    prepare.add_argument("--results-branch", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--taxonomy-file", type=_path, default=CANONICAL_TAXONOMY)
    defaults = BudgetConfiguration()
    prepare.add_argument("--parent-acu", type=int, default=defaults.parent_orchestrator_acu)
    prepare.add_argument("--investigator-acu", type=int, default=defaults.investigator_child_acu)
    prepare.add_argument("--coverage-auditor-acu", type=int, default=defaults.coverage_auditor_acu)
    prepare.add_argument("--validator-acu", type=int, default=defaults.validator_pack_acu)
    prepare.add_argument("--critic-acu", type=int, default=defaults.critic_acu)
    prepare.add_argument("--max-investigation-children", type=int, default=defaults.maximum_investigation_children)
    prepare.add_argument("--max-validation-children", type=int, default=defaults.maximum_validation_children)
    prepare.add_argument("--max-retries", type=int, default=defaults.maximum_retry_count)

    verify_task = commands.add_parser("verify-task", help="verify an investigator child branch artifact tree")
    verify_task.add_argument("--run-dir", type=_path, required=True)
    verify_task.add_argument("--work-package", type=_path, required=True)
    verify_task.add_argument("--child-artifact-dir", type=_path, required=True)
    verify_task.add_argument("--target-repo-path", type=_path, required=True)
    verify_task.add_argument("--changed-path", action="append", default=[])

    for name in ("normalize-findings", "cluster-findings"):
        command = commands.add_parser(name)
        command.add_argument("--run-dir", type=_path, required=True)

    validation_packs = commands.add_parser("create-validation-packs")
    validation_packs.add_argument("--run-dir", type=_path, required=True)

    verify_validation = commands.add_parser("verify-validation")
    verify_validation.add_argument("--run-dir", type=_path, required=True)
    verify_validation.add_argument("--pack", type=_path, required=True)
    verify_validation.add_argument("--finding-id", required=True)
    verify_validation.add_argument("--artifact-dir", type=_path, required=True)
    verify_validation.add_argument("--target-repo-path", type=_path, required=True)
    verify_validation.add_argument("--changed-path", action="append", default=[])

    coverage = commands.add_parser("coverage-audit")
    coverage.add_argument("--run-dir", type=_path, required=True)
    coverage.add_argument("--audit", type=_path, required=True)

    critic = commands.add_parser("apply-critic")
    critic.add_argument("--run-dir", type=_path, required=True)
    critic.add_argument("--critic-result", type=_path, required=True)

    complete = commands.add_parser("completion-gate")
    complete.add_argument("--run-dir", type=_path, required=True)
    complete.add_argument("--target-repo-path", type=_path, required=True)
    return parser


def _validation_results(run_dir: Path) -> list[dict[str, Any]]:
    return [
        read_json(path)["validation_result"]
        for path in sorted((run_dir / "validations").glob("*/verified-receipt.json"))
    ]


def _run(arguments: argparse.Namespace) -> Any:
    if arguments.command == "prepare":
        budgets = BudgetConfiguration(
            parent_orchestrator_acu=arguments.parent_acu,
            investigator_child_acu=arguments.investigator_acu,
            coverage_auditor_acu=arguments.coverage_auditor_acu,
            validator_pack_acu=arguments.validator_acu,
            critic_acu=arguments.critic_acu,
            maximum_investigation_children=arguments.max_investigation_children,
            maximum_validation_children=arguments.max_validation_children,
            maximum_retry_count=arguments.max_retries,
        )
        run_dir, result = prepare_run(
            target_repo_path=arguments.target_repo_path,
            target_repository=arguments.target_repo,
            target_commit=arguments.target_commit,
            results_repo_path=arguments.results_repo_path,
            results_branch=arguments.results_branch,
            run_id=arguments.run_id,
            taxonomy_file=arguments.taxonomy_file,
            budgets=budgets,
        )
        return {"run_dir": str(run_dir), **result}
    if arguments.command == "verify-task":
        return verify_child_task(
            run_dir=arguments.run_dir,
            work_package=read_json(arguments.work_package),
            child_artifact_dir=arguments.child_artifact_dir,
            target_repo_path=arguments.target_repo_path,
            changed_paths=arguments.changed_path,
        )
    if arguments.command == "normalize-findings":
        return {"findings": normalize_run_findings(arguments.run_dir)}
    if arguments.command == "cluster-findings":
        return cluster_run_findings(arguments.run_dir)
    if arguments.command == "create-validation-packs":
        manifest = read_json(arguments.run_dir / "run-manifest.json")
        findings = read_json(arguments.run_dir / "root-causes" / "findings-clustered.json")
        budget_values = manifest["budgets"]
        packs = create_validation_packs(
            run_id=manifest["run_id"],
            target_repository=manifest["target_repository"],
            target_commit=manifest["target_commit"],
            findings=findings,
            maximum_children=int(budget_values["maximum_validation_children"]),
            maximum_acu=int(budget_values["validator_pack_acu"]),
        )
        for pack in packs:
            value = pack.as_dict()
            validate_artifact(value, "validation-pack.schema.json")
            write_json(arguments.run_dir / "validation-packs" / f"{pack.pack_id}.json", value)
        AuditLog(arguments.run_dir / "audit-log.jsonl").append(
            "validation_packs_created",
            run_id=str(manifest["run_id"]),
            details={"pack_ids": [pack.pack_id for pack in packs], "finding_count": len(findings)},
        )
        return {"validation_packs": [pack.as_dict() for pack in packs]}
    if arguments.command == "verify-validation":
        return verify_validation_result(
            run_dir=arguments.run_dir,
            pack=read_json(arguments.pack),
            finding_id=arguments.finding_id,
            artifact_dir=arguments.artifact_dir,
            target_repo_path=arguments.target_repo_path,
            changed_paths=arguments.changed_path,
        )
    if arguments.command == "coverage-audit":
        return coverage_audit_run(arguments.run_dir, arguments.audit)
    if arguments.command == "apply-critic":
        manifest = read_json(arguments.run_dir / "run-manifest.json")
        critic = read_json(arguments.critic_result)
        findings = read_json(arguments.run_dir / "root-causes" / "findings-clustered.json")
        final = apply_critic_results(
            findings=findings,
            validation_results=_validation_results(arguments.run_dir),
            critic=critic,
            run_id=manifest["run_id"],
            target_repository=manifest["target_repository"],
            target_commit=manifest["target_commit"],
        )
        write_json(arguments.run_dir / "critic" / "critic-result.json", critic)
        write_json(arguments.run_dir / "critic" / "findings-reviewed.json", final)
        AuditLog(arguments.run_dir / "audit-log.jsonl").append(
            "critic_results_applied",
            run_id=str(manifest["run_id"]),
            details={
                "decision_count": len(critic["decisions"]),
                "final_finding_count": len(final),
                "verdicts": {
                    item["finding_id"]: item["verdict"] for item in sorted(critic["decisions"], key=lambda value: value["finding_id"])
                },
            },
        )
        return {"findings": final}
    if arguments.command == "completion-gate":
        return completion_gate(run_dir=arguments.run_dir, target_repo_path=arguments.target_repo_path)
    raise OperationalError(f"unsupported command: {arguments.command}")


def main(argv: list[str] | None = None) -> int:
    try:
        result = _run(_parser().parse_args(argv))
        _emit(result)
        return 0
    except ManagedScanError as exc:
        print(f"hunter-managed: {exc}", file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"hunter-managed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
