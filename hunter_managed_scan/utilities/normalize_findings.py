"""Mechanically normalize verified investigator findings and CVSS arithmetic."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from hunter_managed_scan.errors import VerificationError
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.cvss import calculate_base_score
from hunter_managed_scan.utilities.json_io import read_json, write_json
from hunter_managed_scan.utilities.schema_validation import validate_artifact


def normalize_findings(
    receipts: Iterable[dict[str, Any]], *, target_commit: str
) -> list[dict[str, Any]]:
    """Return schema-valid candidates with mechanically recomputed CVSS scores.

    This function deliberately does not decide whether any candidate is a
    vulnerability.  It only accepts candidates that already passed child
    artifact and excerpt verification.
    """

    normalized: list[dict[str, Any]] = []
    finding_ids: set[str] = set()
    for receipt in receipts:
        if receipt.get("verification_status") != "ACCEPTED":
            raise VerificationError("normalization input contains an unaccepted child receipt")
        for value in receipt.get("findings", []):
            finding = deepcopy(value)
            validate_artifact(finding, "finding.schema.json")
            if finding["target_commit"] != target_commit:
                raise VerificationError("finding target commit does not match the run manifest")
            finding_id = str(finding["finding_id"])
            if finding_id in finding_ids:
                raise VerificationError(f"duplicate finding ID before clustering: {finding_id}")
            finding_ids.add(finding_id)
            finding["cvss_score"] = calculate_base_score(str(finding["cvss_vector"]))
            finding["status"] = "VERIFIED_CANDIDATE"
            validate_artifact(finding, "finding.schema.json")
            normalized.append(finding)
    return sorted(normalized, key=lambda item: item["finding_id"])


def normalize_run_findings(run_dir: Path) -> list[dict[str, Any]]:
    manifest = read_json(run_dir / "run-manifest.json")
    receipt_paths = sorted((run_dir / "investigation" / "verified").glob("*.json"))
    receipts = [read_json(path) for path in receipt_paths]
    findings = normalize_findings(receipts, target_commit=str(manifest["target_commit"]))
    write_json(run_dir / "investigation" / "normalized" / "findings.json", findings)
    AuditLog(run_dir / "audit-log.jsonl").append(
        "finding_normalization",
        run_id=str(manifest["run_id"]),
        details={"accepted_receipts": len(receipts), "normalized_findings": len(findings)},
    )
    return findings
