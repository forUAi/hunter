"""Bounded investigation and independent coverage-audit work packages."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class WorkPackage:
    run_id: str
    task_id: str
    task_kind: str
    target_repository: str
    target_commit: str
    assigned_classes: tuple[int, ...]
    candidate_files: tuple[str, ...]
    security_surfaces: tuple[str, ...]
    logic_targets: tuple[dict[str, Any], ...]
    matcher_evidence: tuple[dict[str, Any], ...]
    negative_evidence_to_review: tuple[dict[str, Any], ...]
    questions: tuple[str, ...]
    result_branch: str
    maximum_acu: int
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in (
            "assigned_classes",
            "candidate_files",
            "security_surfaces",
            "logic_targets",
            "matcher_evidence",
            "negative_evidence_to_review",
            "questions",
        ):
            result[key] = list(result[key])
        return result
