"""Fresh-context Critic verdict models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CriticDecision:
    finding_id: str
    verdict: str
    reason: str
    corrected_severity: str | None = None
    corrected_cvss_vector: str | None = None
    contradicting_evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["contradicting_evidence"] = list(self.contradicting_evidence)
        return result


@dataclass(frozen=True)
class CriticResult:
    run_id: str
    target_repository: str
    target_commit: str
    produced_by: str
    decisions: tuple[CriticDecision, ...]
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "target_repository": self.target_repository,
            "target_commit": self.target_commit,
            "produced_by": self.produced_by,
            "decisions": [decision.as_dict() for decision in self.decisions],
        }
