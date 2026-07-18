"""Grouped validation-pack and per-finding runtime result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ValidationPack:
    run_id: str
    pack_id: str
    target_repository: str
    target_commit: str
    environment_family: str
    finding_ids: tuple[str, ...]
    setup_plan: tuple[str, ...]
    build_once: bool
    maximum_acu: int
    result_branch: str
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["finding_ids"] = list(self.finding_ids)
        result["setup_plan"] = list(self.setup_plan)
        return result


@dataclass(frozen=True)
class ValidationResult:
    finding_id: str
    validation_status: str
    summary: str
    actual_claim_tested: str
    environment: dict[str, Any]
    setup: tuple[str, ...]
    reproduction_steps: tuple[str, ...]
    commands: tuple[dict[str, Any], ...]
    observed_outcome: str
    control_outcome: str
    artifacts: tuple[str, ...]
    limitations: tuple[str, ...]
    reachability_effect: str
    severity_effect: str
    confidence_effect: str
    recommended_follow_up: str
    blocking_condition: str = ""
    missing_evidence: tuple[str, ...] = ()
    confirmation_criteria: str = ""
    target_commit: str = ""
    produced_by: str = ""
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("setup", "reproduction_steps", "commands", "artifacts", "limitations", "missing_evidence"):
            result[key] = list(result[key])
        return result
