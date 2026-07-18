"""Mechanically apply fresh-context Critic decisions."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from hunter_managed_scan.errors import MissingValidationError, VerificationError
from hunter_managed_scan.utilities.cvss import calculate_base_score, severity_for_score
from hunter_managed_scan.utilities.schema_validation import validate_artifact


def apply_critic_results(
    *,
    findings: list[dict[str, Any]],
    validation_results: list[dict[str, Any]],
    critic: dict[str, Any],
    run_id: str,
    target_repository: str,
    target_commit: str,
) -> list[dict[str, Any]]:
    validate_artifact(critic, "critic-result.schema.json")
    for key, expected in {
        "run_id": run_id,
        "target_repository": target_repository,
        "target_commit": target_commit,
    }.items():
        if critic.get(key) != expected:
            raise VerificationError(f"critic result has wrong {key}")
    finding_by_id = {item["finding_id"]: item for item in findings}
    validation_by_id = {item["finding_id"]: item for item in validation_results}
    if len(validation_by_id) != len(validation_results) or set(validation_by_id) != set(finding_by_id):
        raise MissingValidationError("every verified finding must have exactly one validation result")
    decisions = critic["decisions"]
    decision_ids = [item["finding_id"] for item in decisions]
    if len(decision_ids) != len(set(decision_ids)) or set(decision_ids) != set(finding_by_id):
        raise VerificationError("critic must decide every finding exactly once")

    final: list[dict[str, Any]] = []
    for decision in sorted(decisions, key=lambda item: item["finding_id"]):
        finding_id = decision["finding_id"]
        validation = validation_by_id[finding_id]
        if validation["validation_status"] == "FALSE_POSITIVE" and decision["verdict"] != "REJECTED":
            raise VerificationError("critic must reject a finding with FALSE_POSITIVE validation")
        if decision["verdict"] == "REJECTED":
            continue
        finding = deepcopy(finding_by_id[finding_id])
        finding["validation"] = validation
        finding["critic"] = decision
        if decision["verdict"] == "DOWNGRADED":
            severity = decision.get("corrected_severity")
            vector = decision.get("corrected_cvss_vector")
            if not severity or not vector:
                raise VerificationError("critic downgrade lacks corrected severity or CVSS vector")
            score = calculate_base_score(vector)
            if severity != severity_for_score(score) or score > float(finding["cvss_score"]):
                raise VerificationError("critic downgrade severity/vector arithmetic is inconsistent")
            finding["severity"] = severity
            finding["cvss_vector"] = vector
            finding["cvss_score"] = score
        else:
            expected = calculate_base_score(str(finding["cvss_vector"]))
            if expected != float(finding["cvss_score"]):
                raise VerificationError("confirmed finding CVSS arithmetic is inconsistent")
        final.append(finding)
    return sorted(final, key=lambda item: item["finding_id"])
