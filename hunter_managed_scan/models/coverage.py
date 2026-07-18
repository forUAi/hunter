"""Complete 85-class coverage ledger models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

PRELIMINARY_STATES = frozenset(
    {
        "ASSIGNED_TO_INVESTIGATION",
        "NEGATIVE_EVIDENCE_REVIEW",
        "ALWAYS_CHECK",
        "UNRESOLVED",
        "DOWNSTREAM_CHAIN_REVIEW",
    }
)


@dataclass(frozen=True)
class CoverageEntry:
    class_number: int
    class_name: str
    preliminary_state: str
    task_ids: tuple[str, ...] = ()
    candidate_files: tuple[str, ...] = ()
    carrier_evidence: tuple[dict[str, Any], ...] = ()
    negative_evidence: tuple[dict[str, Any], ...] = ()
    logic_targets: tuple[dict[str, Any], ...] = ()
    requires_manual_review: bool = True

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("task_ids", "candidate_files", "carrier_evidence", "negative_evidence", "logic_targets"):
            result[key] = list(result[key])
        return result


@dataclass(frozen=True)
class CoveragePlan:
    run_id: str
    target_repository: str
    target_commit: str
    taxonomy_version: str
    entries: tuple[CoverageEntry, ...] = field(default_factory=tuple)
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "target_repository": self.target_repository,
            "target_commit": self.target_commit,
            "taxonomy_version": self.taxonomy_version,
            "entries": [entry.as_dict() for entry in self.entries],
        }
