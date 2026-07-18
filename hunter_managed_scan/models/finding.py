"""Investigator-produced finding models; construction does not imply validity."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AffectedInstance:
    file: str
    start_line: int
    end_line: int
    excerpt: str
    excerpt_sha256: str
    component: str
    endpoint_or_workflow: str
    production_relevance: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    class_number: int
    class_name: str
    category: str
    cwe: str
    owasp: str
    title: str
    description: str
    severity: str
    cvss_vector: str
    cvss_score: float
    confidence: str
    status: str
    security_property: str
    root_cause_candidate: str
    source: str
    sink: str
    attack_path: tuple[str, ...]
    preconditions: tuple[str, ...]
    reachability: str
    mitigations_checked: tuple[str, ...]
    affected_instances: tuple[AffectedInstance, ...]
    evidence: tuple[str, ...]
    remediation_recommendation: str
    produced_by: str
    target_commit: str

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("attack_path", "preconditions", "mitigations_checked", "evidence"):
            result[key] = list(result[key])
        result["affected_instances"] = [instance.as_dict() for instance in self.affected_instances]
        return result
