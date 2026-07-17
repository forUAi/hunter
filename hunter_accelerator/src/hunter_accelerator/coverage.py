"""Fail-closed Phase 1 coverage-gap detection."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .hashing import stable_id
from .models import CarrierEvidence, LogicTarget, SkippedEntry, TaxonomyBundle, UnsupportedConstruct


def evaluate_coverage(
    taxonomy: TaxonomyBundle,
    decisions: list[dict[str, Any]],
    matchers: list[dict[str, Any]],
    logic_targets: list[LogicTarget],
    carriers: list[CarrierEvidence],
    skipped: list[SkippedEntry],
    unsupported: list[UnsupportedConstruct],
    git_metadata_status: str,
    git_metadata_reason: str | None,
) -> list[dict[str, Any]]:
    matcher_counts = Counter(int(item["class_number"]) for item in matchers)
    absence_matcher_counts = Counter(
        int(item["class_number"]) for item in matchers if bool(item.get("absence_detection"))
    )
    target_counts: Counter[int] = Counter()
    for target in logic_targets:
        target_counts.update(target.activated_classes)
    gaps: list[dict[str, Any]] = []

    def add(kind: str, message: str, classes: list[int] | tuple[int, ...], evidence: list[dict[str, Any]]) -> None:
        gaps.append(
            {
                "gap_id": stable_id("coverage-gap", kind, message, *classes, length=20),
                "condition": kind,
                "affected_classes": sorted(set(classes)),
                "message": message,
                "evidence": evidence,
                "required_action": "Run the original Hunter All matcher process for this area; accelerator completion is not sufficient.",
            }
        )

    for decision in decisions:
        number = int(decision["class_number"])
        applicable = decision["status"] in {"ALWAYS_APPLICABLE", "APPLICABLE"}
        handoff = bool(decision.get("downstream_handoff"))
        if applicable and not handoff and not matcher_counts[number] and not target_counts[number]:
            add("applicable_class_without_matcher", f"Applicable class {number} has no matcher or logic target.", [number], [])
        if number in taxonomy.always_applicable and not matcher_counts[number] and not target_counts[number]:
            add("always_applicable_without_coverage", f"Always-applicable class {number} has no matcher or logic target.", [number], [])
        if number in taxonomy.absence_classes and applicable and not absence_matcher_counts[number]:
            add("absence_class_without_control_location_matcher", f"Absence class {number} has no control-location matcher.", [number], [])
        if decision["status"] == "UNRESOLVED":
            add(
                "unresolved_applicability",
                f"Class {number} applicability is unresolved.",
                [number],
                decision["skipped_files_affecting_confidence"] + decision["unsupported_constructs"],
            )

    if git_metadata_status == "unresolved":
        reason = git_metadata_reason or "Git metadata could not be safely resolved"
        add(
            "git_metadata_unresolved",
            f"Class 24 Git metadata is unresolved: {reason}.",
            [24],
            [{"path": ".git", "git_metadata_status": git_metadata_status, "reason": reason}],
        )

    for entry in skipped:
        if entry.security_relevant:
            affected = sorted(
                {
                    number
                    for item in taxonomy.classes
                    for number in [int(item["class_number"])]
                    if not entry.carrier_hints or set(item["carriers"]) & set(entry.carrier_hints)
                }
            )
            add(
                "security_relevant_file_skipped",
                f"Security-relevant {entry.entry_type} was skipped: {entry.relative_path} ({entry.reason}).",
                affected,
                [entry.as_json()],
            )

    for construct in unsupported:
        add(
            "unsupported_security_construct",
            f"Unsupported construct in {construct.file}: {construct.construct_type}.",
            list(construct.affected_categories),
            [construct.as_json()],
        )
        if construct.construct_type == "generated route":
            add(
                "logic_target_not_enumerated",
                f"Generated route targets could not be completely enumerated in {construct.file}.",
                [10, 11, 12, 14, 49, 50, 55, 56, 57],
                [construct.as_json()],
            )

    modeled_carriers = {carrier for item in taxonomy.classes for carrier in item["carriers"]}
    modeled_carriers.update({"container CI/CD", "cloud SDK", "internal framework"})
    unmodeled: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for carrier in carriers:
        if carrier.carrier_type not in modeled_carriers or not carrier.classes_activated:
            unmodeled[carrier.carrier_type].append(carrier.as_json())
    for carrier_type, evidence in sorted(unmodeled.items()):
        if carrier_type == "internal framework":
            continue
        add(
            "carrier_without_category_model",
            f"Carrier type {carrier_type} has no category model.",
            [],
            evidence[:20],
        )

    unique = {(item["condition"], item["message"]): item for item in gaps}
    return [unique[key] for key in sorted(unique, key=lambda key: (key[0], key[1]))]
