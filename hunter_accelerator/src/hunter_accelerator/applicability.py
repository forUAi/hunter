"""Four-layer Hunter All applicability engine with evidence-bound N/A decisions."""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from .hashing import stable_id
from .models import CarrierEvidence, FileRecord, SkippedEntry, TaxonomyBundle, UnsupportedConstruct


def _matches_globs(path: str, globs: list[str]) -> bool:
    if not globs or "**/*" in globs:
        return True
    name = PurePosixPath(path).name
    return any(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(name, glob.removeprefix("**/")) for glob in globs)


def decide_applicability(
    taxonomy: TaxonomyBundle,
    records: list[FileRecord],
    skipped: list[SkippedEntry],
    carriers: list[CarrierEvidence],
    unsupported: list[UnsupportedConstruct],
    negative_matches: dict[int, list[dict[str, Any]]],
    has_git_history: bool,
    git_metadata_status: str,
) -> list[dict[str, Any]]:
    evidence_by_class: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for evidence in carriers:
        serialized = evidence.as_json()
        reference = {
            "evidence_id": serialized["carrier_id"],
            "carrier_type": evidence.carrier_type,
            "file": evidence.file,
            "line": evidence.line,
            "evidence": evidence.evidence,
        }
        for number in evidence.classes_activated:
            evidence_by_class[number].append(reference)
    if has_git_history:
        evidence_by_class[24].append(
            {"carrier_type": "git history", "file": ".git", "line": None, "evidence": "Git history is available"}
        )
    for number, matches in negative_matches.items():
        for match in matches:
            evidence_by_class[number].append(
                {
                    "evidence_id": stable_id(
                        "search-evidence",
                        number,
                        match["file"],
                        match["line"],
                        match["indicator"],
                        length=20,
                    ),
                    "carrier_type": "class-specific search",
                    "file": match["file"],
                    "line": match["line"],
                    "evidence": f"matched configured indicator: {match['indicator']}",
                }
            )

    skipped_carriers: set[str] = set()
    for entry in skipped:
        if entry.security_relevant:
            skipped_carriers.update(entry.carrier_hints)
    unresolved_by_class: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for construct in unsupported:
        for number in construct.affected_categories:
            unresolved_by_class[number].append(construct.as_json())

    decisions: list[dict[str, Any]] = []
    for item in taxonomy.classes:
        number = int(item["class_number"])
        configured_carriers = [str(value) for value in item["carriers"]]
        inspected_paths = sorted(
            record.relative_path for record in records if _matches_globs(record.relative_path, item["target_file_globs"])
        )
        positives = evidence_by_class[number]
        unique_positives = {
            (value["carrier_type"], value["file"], value["line"], value["evidence"]): value for value in positives
        }
        positives = [
            unique_positives[key]
            for key in sorted(unique_positives, key=lambda key: (key[0], key[1], key[2] or 0, key[3]))
        ]
        relevant_skips = [
            entry.as_json()
            for entry in skipped
            if entry.security_relevant and (not entry.carrier_hints or set(entry.carrier_hints) & set(configured_carriers))
        ]
        unresolved_constructs = unresolved_by_class[number]

        if number in taxonomy.always_applicable:
            status = "ALWAYS_APPLICABLE"
            reason = "Hunter All always-applicable tier; N/A is prohibited."
        elif number == 58:
            status = "APPLICABLE"
            reason = "Hunter All requires Class 58 to be handled in downstream aggregation; Phase 1 emits a handoff only."
        elif number == 24 and git_metadata_status == "unresolved":
            status = "UNRESOLVED"
            reason = "Git metadata exists but could not be safely resolved; Class 24 cannot be marked N/A."
        elif positives:
            status = "APPLICABLE"
            reason = "At least one configured carrier or class-specific signal exists."
        elif relevant_skips or unresolved_constructs or set(configured_carriers) & skipped_carriers:
            status = "UNRESOLVED"
            reason = "Carrier absence cannot be proven because relevant files or constructs were not fully analyzed."
        else:
            status = "NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE"
            reason = "Every configured carrier search completed with zero relevant carriers."

        patterns = [str(value) for value in item["negative_evidence_searches"]]
        negative_summary = (
            f"searched carrier types {', '.join(configured_carriers) or '<none>'} and "
            f"{len(patterns)} configured indicator(s) across {len(inspected_paths)} eligible file(s); "
            + ("zero relevant carriers or matches" if not positives else f"{len(positives)} positive evidence item(s)")
        )
        decisions.append(
            {
                "class_number": number,
                "class_name": item["class_name"],
                "owasp": item["owasp"],
                "status": status,
                "reason": reason,
                "always_applicable": bool(item["always_applicable"]),
                "absence_class": bool(item["absence_class"]),
                "logic_class": bool(item["logic_class"]),
                "searched_carrier_types": configured_carriers,
                "search_patterns": patterns,
                "files_inspected": {"count": len(inspected_paths), "paths": inspected_paths[:200], "truncated": len(inspected_paths) > 200},
                "positive_matches": positives[:100],
                "positive_matches_truncated": len(positives) > 100,
                "negative_search_summary": negative_summary,
                "skipped_files_affecting_confidence": relevant_skips,
                "unsupported_constructs": unresolved_constructs,
                "downstream_handoff": number == 58,
                "git_metadata_status": git_metadata_status if number == 24 else None,
            }
        )
    return decisions
