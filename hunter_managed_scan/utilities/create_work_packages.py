"""Deterministically group coverage by security surface rather than matcher count."""

from __future__ import annotations

from typing import Any

from hunter_managed_scan.adapters.matcher_adapter import matcher_leads_for_classes
from hunter_managed_scan.models.coverage import CoveragePlan
from hunter_managed_scan.models.manifest import BudgetConfiguration
from hunter_managed_scan.models.work_package import WorkPackage

TASK_QUESTIONS = {
    "investigator-authz-business": (
        "Trace subject-to-object authorization and ownership decisions for every assigned route and logic target.",
        "Check business invariants, state transitions, idempotency, audit integrity, and failure paths.",
    ),
    "investigator-injection-execution": (
        "Trace untrusted sources through parsers, queries, requests, files, templates, and execution sinks.",
        "Document reachability and every mitigation before reporting a candidate.",
    ),
    "investigator-data-trust": (
        "Review secrets, cryptography, logging, privacy, configuration, and sensitive-data boundaries.",
        "Preserve distinct security properties and affected workflows.",
    ),
    "investigator-supply-chain": (
        "Review dependencies, source integrity, Git history, CI/CD, licenses, and build trust boundaries.",
        "Treat deterministic matcher output only as bounded leads.",
    ),
    "investigator-platform-ai": (
        "Review infrastructure, containers, cloud, mobile, LLM, Agentic, prompt, tool, MCP, and memory surfaces.",
        "Separate incompatible runtime environments and abstain when repository evidence is insufficient.",
    ),
    "coverage-auditor": (
        "Independently account for all 85 classes and review every negative-evidence claim.",
        "Record unresolved coverage rather than inferring safety or silently skipping a class.",
    ),
}


def create_work_packages(
    *,
    plan: CoveragePlan,
    preparation: dict[str, Any],
    budgets: BudgetConfiguration,
) -> list[WorkPackage]:
    packages: list[WorkPackage] = []
    task_ids = sorted({task_id for entry in plan.entries for task_id in entry.task_ids})
    for task_id in task_ids:
        entries = [entry for entry in plan.entries if task_id in entry.task_ids]
        class_numbers = {entry.class_number for entry in entries}
        audit = task_id == "coverage-auditor"
        bounded_entries = entries
        files = sorted({path for entry in bounded_entries for path in entry.candidate_files})[:200]
        surfaces = sorted(
            {
                str(item.get("carrier_type"))
                for entry in bounded_entries
                for item in entry.carrier_evidence
                if item.get("carrier_type")
            }
        )
        logic_targets = {
            str(item["target_id"]): item
            for entry in entries
            for item in entry.logic_targets
        }
        matchers = matcher_leads_for_classes(preparation["matchers"], class_numbers)
        negative = [entry.negative_evidence[0] for entry in bounded_entries if entry.negative_evidence]
        coverage_context = (
            tuple(
                {
                    "class_number": entry.class_number,
                    "class_name": entry.class_name,
                    "preliminary_state": entry.preliminary_state,
                    "domain_owner": next(value for value in entry.task_ids if value != "coverage-auditor"),
                    "top_carrier_evidence": list(entry.carrier_evidence[:3]),
                    "negative_evidence": list(entry.negative_evidence[:1]),
                    "candidate_files": list(entry.candidate_files[:5]),
                    "logic_targets": list(entry.logic_targets[:3]),
                    "investigator_outcome": None,
                }
                for entry in entries
            )
            if audit
            else ()
        )
        packages.append(
            WorkPackage(
                run_id=plan.run_id,
                task_id=task_id,
                task_kind="COVERAGE_AUDIT" if audit else "INVESTIGATION",
                target_repository=plan.target_repository,
                target_commit=plan.target_commit,
                assigned_classes=tuple(sorted(class_numbers)),
                candidate_files=tuple(files),
                security_surfaces=tuple(surfaces),
                logic_targets=tuple(logic_targets[key] for key in sorted(logic_targets)),
                matcher_evidence=tuple(matchers),
                negative_evidence_to_review=tuple(negative),
                coverage_context=coverage_context,
                unsupported_constructs=tuple(preparation.get("unsupported", [])[:100]) if audit else (),
                questions=TASK_QUESTIONS[task_id],
                result_branch=f"hunter-run/{plan.run_id}/{task_id}",
                maximum_acu=(budgets.coverage_auditor_acu if audit else budgets.investigator_child_acu),
            )
        )
    if len(packages) > budgets.maximum_investigation_children:
        raise ValueError("work-package count exceeds configured investigation-child limit")
    return sorted(packages, key=lambda item: item.task_id)
