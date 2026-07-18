"""Small deterministic test values."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from typing import Any


VECTOR_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
VECTOR_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L"


def finding(
    finding_id: str = "HMS-001",
    *,
    file: str = "src/app.py",
    excerpt: str = "dangerous(user_input)",
    workflow: str = "POST /accounts/{id}",
    class_number: int = 1,
    vector: str = VECTOR_HIGH,
    score: float = 8.8,
    root_cause: str = "untrusted input reaches the sink",
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "class_number": class_number,
        "class_name": "SQL Injection",
        "category": "Injection",
        "cwe": "CWE-89",
        "owasp": "A05",
        "title": "Candidate unsafe query construction",
        "description": "A verified investigator candidate requiring runtime validation.",
        "severity": "HIGH",
        "cvss_vector": vector,
        "cvss_score": score,
        "confidence": "HIGH",
        "status": "CANDIDATE",
        "security_property": "query structure integrity",
        "root_cause_candidate": root_cause,
        "source": "request input",
        "sink": "database query",
        "attack_path": ["request", "handler", "query"],
        "preconditions": ["attacker can call the endpoint"],
        "reachability": "reachable through the documented route",
        "mitigations_checked": ["parameter binding was reviewed"],
        "affected_instances": [
            {
                "file": file,
                "start_line": 1,
                "end_line": 1,
                "excerpt": excerpt,
                "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
                "component": "account API",
                "endpoint_or_workflow": workflow,
                "production_relevance": "production route",
            }
        ],
        "evidence": ["exact source excerpt verified by parent"],
        "remediation_recommendation": "Use a structured parameterized query.",
        "produced_by": "investigator-injection-execution",
        "target_commit": "a" * 40,
    }


def validation(finding_id: str = "HMS-001", status: str = "CONFIRMED") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "finding_id": finding_id,
        "validation_status": status,
        "summary": "A local harness exercised the actual claim and a control.",
        "actual_claim_tested": "Input changes query structure in the relevant library.",
        "environment": {"runtime": "fixture-python"},
        "setup": ["Created an isolated local harness."],
        "reproduction_steps": ["Executed payload and a benign control."],
        "commands": [{"command": "python fixture_probe.py", "exit_code": 0}],
        "observed_outcome": "The proof path reached the instrumented sink.",
        "control_outcome": "The control preserved query structure.",
        "artifacts": ["output.txt"],
        "limitations": ["Local fixture only."],
        "reachability_effect": "Supports local reachability.",
        "severity_effect": "No mechanical change.",
        "confidence_effect": "Raises confidence.",
        "recommended_follow_up": "Critic review.",
        "blocking_condition": "",
        "missing_evidence": [],
        "confirmation_criteria": "",
        "target_commit": "a" * 40,
        "produced_by": "validator-python-1",
    }


def preparation(carriers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "applicability": [
            {"class_number": number, "status": "APPLICABLE", "positive_matches": []}
            for number in range(1, 86)
        ],
        "negative_evidence": [
            {"class_number": number, "searches": [], "matches": [], "interpretation": "review required"}
            for number in range(1, 86)
        ],
        "carriers": carriers or [],
        "logic_targets": [],
        "matchers": [],
    }


def clone(value: Any) -> Any:
    return deepcopy(value)
