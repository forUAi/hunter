"""Build a complete fail-closed ledger without semantic vulnerability decisions."""

from __future__ import annotations

from typing import Any

from hunter_managed_scan.adapters.carrier_adapter import candidate_files, class_specific_evidence
from hunter_managed_scan.adapters.logic_target_adapter import logic_targets_for_classes
from hunter_managed_scan.errors import IncompleteCoverageError
from hunter_managed_scan.models.coverage import CoverageEntry, CoveragePlan


def specialist_task_for_class(number: int) -> str:
    if number in set(range(1, 10)) | {13, 17, 23, 31, 32, 47, 53, 54}:
        return "investigator-injection-execution"
    if number in set(range(10, 21)) | set(range(27, 33)) | set(range(48, 58)):
        return "investigator-authz-business"
    if number == 24 or 43 <= number <= 46:
        return "investigator-supply-chain"
    if 59 <= number <= 85:
        return "investigator-platform-ai"
    return "investigator-data-trust"


def create_coverage_plan(
    *,
    run_id: str,
    target_repository: str,
    target_commit: str,
    taxonomy: Any,
    preparation: dict[str, Any],
) -> CoveragePlan:
    applicability = {int(item["class_number"]): item for item in preparation["applicability"]}
    negative = {int(item["class_number"]): item for item in preparation["negative_evidence"]}
    entries: list[CoverageEntry] = []
    for item in taxonomy.classes:
        number = int(item["class_number"])
        application = applicability[number]
        evidence = class_specific_evidence(number, preparation["carriers"], application)
        logic_targets = logic_targets_for_classes(preparation["logic_targets"], {number})
        if number in taxonomy.always_applicable:
            state = "ALWAYS_CHECK"
        elif number == 58:
            state = "DOWNSTREAM_CHAIN_REVIEW"
        elif application["status"] == "UNRESOLVED":
            state = "UNRESOLVED"
        elif evidence:
            state = "ASSIGNED_TO_INVESTIGATION"
        else:
            state = "NEGATIVE_EVIDENCE_REVIEW"
        task_ids = (specialist_task_for_class(number), "coverage-auditor")
        entries.append(
            CoverageEntry(
                class_number=number,
                class_name=str(item["class_name"]),
                preliminary_state=state,
                task_ids=task_ids,
                candidate_files=tuple(candidate_files(evidence)),
                carrier_evidence=tuple(evidence),
                negative_evidence=(negative[number],),
                logic_targets=tuple(logic_targets),
                requires_manual_review=True,
            )
        )
    numbers = [entry.class_number for entry in entries]
    if numbers != list(range(1, 86)):
        raise IncompleteCoverageError("coverage plan does not contain ordered classes 1 through 85")
    return CoveragePlan(
        run_id=run_id,
        target_repository=target_repository,
        target_commit=target_commit,
        taxonomy_version=taxonomy.version,
        entries=tuple(entries),
    )
