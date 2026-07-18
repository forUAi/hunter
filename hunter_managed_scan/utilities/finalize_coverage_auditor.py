"""Attach accepted domain-investigator outcomes to the auditor work package."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError, VerificationError
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.json_io import read_json, write_json
from hunter_managed_scan.utilities.schema_validation import validate_artifact


def finalize_coverage_auditor_package(run_dir: Path) -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    package_path = run_dir / "work-packages" / "coverage-auditor.json"
    package = read_json(package_path)
    if package.get("task_kind") != "COVERAGE_AUDIT":
        raise VerificationError("coverage-auditor work package has the wrong task kind")
    finalized = deepcopy(package)
    for context in finalized["coverage_context"]:
        owner = str(context["domain_owner"])
        receipt_path = run_dir / "investigation" / "verified" / f"{owner}.json"
        if not receipt_path.is_file():
            raise IncompleteCoverageError(
                f"domain investigator outcome is missing before coverage audit: {owner}"
            )
        receipt = read_json(receipt_path)
        if receipt.get("verification_status") != "ACCEPTED":
            raise IncompleteCoverageError(f"domain investigator receipt is not accepted: {owner}")
        number = int(context["class_number"])
        outcomes = [item for item in receipt.get("coverage", []) if int(item.get("class_number", 0)) == number]
        if len(outcomes) != 1:
            raise IncompleteCoverageError(
                f"domain investigator {owner} did not provide exactly one outcome for class {number}"
            )
        outcome = deepcopy(outcomes[0])
        outcome["finding_ids"] = sorted(
            finding["finding_id"]
            for finding in receipt.get("findings", [])
            if int(finding["class_number"]) == number
        )
        context["investigator_outcome"] = outcome
    context_numbers = [int(item["class_number"]) for item in finalized["coverage_context"]]
    if context_numbers != list(range(1, 86)) or any(
        item["investigator_outcome"] is None for item in finalized["coverage_context"]
    ):
        raise IncompleteCoverageError("coverage-auditor package is missing one or more domain outcomes")
    validate_artifact(finalized, "work-package.schema.json")
    write_json(package_path, finalized)
    AuditLog(run_dir / "audit-log.jsonl").append(
        "coverage_auditor_package_finalized",
        run_id=str(manifest["run_id"]),
        details={"class_count": 85, "domain_outcomes_attached": 85},
    )
    return finalized
