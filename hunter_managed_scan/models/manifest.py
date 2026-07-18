"""Run identity, immutable target snapshot, and ACU budget models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from hunter_managed_scan import (
    DEFAULT_COVERAGE_AUDITOR_ACU,
    DEFAULT_CRITIC_ACU,
    DEFAULT_INVESTIGATOR_ACU,
    DEFAULT_MAX_INVESTIGATION_CHILDREN,
    DEFAULT_MAX_RETRIES,
    DEFAULT_MAX_VALIDATION_CHILDREN,
    DEFAULT_MAXIMUM_TOTAL_ACU,
    DEFAULT_PARENT_ACU,
    DEFAULT_VALIDATOR_ACU,
)


@dataclass(frozen=True)
class TargetSnapshot:
    commit_sha: str
    status_porcelain: str
    diff_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BudgetConfiguration:
    maximum_total_acu: int = DEFAULT_MAXIMUM_TOTAL_ACU
    parent_orchestrator_acu: int = DEFAULT_PARENT_ACU
    investigator_child_acu: int = DEFAULT_INVESTIGATOR_ACU
    coverage_auditor_acu: int = DEFAULT_COVERAGE_AUDITOR_ACU
    validator_pack_acu: int = DEFAULT_VALIDATOR_ACU
    critic_acu: int = DEFAULT_CRITIC_ACU
    maximum_investigation_children: int = DEFAULT_MAX_INVESTIGATION_CHILDREN
    maximum_validation_children: int = DEFAULT_MAX_VALIDATION_CHILDREN
    maximum_retry_count: int = DEFAULT_MAX_RETRIES

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    target_repository: str
    target_repo_path: str
    target_commit: str
    results_repo_path: str
    results_branch: str
    taxonomy_file: str
    taxonomy_version: str
    accelerator_status: str
    created_at: str
    initial_target_snapshot: TargetSnapshot
    budgets: BudgetConfiguration = field(default_factory=BudgetConfiguration)
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        return result
