"""Completion-gated final output model."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FinalOutput:
    run_id: str
    target_repository: str
    target_commit: str
    status: str
    findings: tuple[dict[str, Any], ...]
    coverage_summary: dict[str, Any]
    validation_summary: dict[str, Any]
    critic_summary: dict[str, Any]
    acu_usage: dict[str, Any]
    schema_version: int = 1

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["findings"] = list(self.findings)
        return result
