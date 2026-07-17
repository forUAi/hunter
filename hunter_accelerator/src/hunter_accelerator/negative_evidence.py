"""Class-specific negative-evidence searches executed during the single file read."""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath
from typing import Any

from .models import FileRecord, SkippedEntry, TaxonomyBundle


class NegativeEvidenceSearcher:
    def __init__(self, taxonomy: TaxonomyBundle) -> None:
        self.taxonomy = taxonomy
        self.patterns: dict[int, tuple[tuple[str, re.Pattern[str]], ...]] = {}
        for item in taxonomy.classes:
            number = int(item["class_number"])
            self.patterns[number] = tuple(
                (str(term), re.compile(re.escape(str(term)), re.IGNORECASE))
                for term in item["negative_evidence_searches"]
                if str(term) and not str(term).startswith("*.") and str(term) != ".git history availability"
            )

    @staticmethod
    def _glob_matches(path: str, globs: list[str]) -> bool:
        if not globs or "**/*" in globs:
            return True
        name = PurePosixPath(path).name
        return any(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(name, glob.removeprefix("**/")) for glob in globs)

    def search_file(self, record: FileRecord, text: str | None) -> tuple[dict[str, tuple[dict[str, Any], ...]], int]:
        results: dict[str, tuple[dict[str, Any], ...]] = {}
        searches = 0
        for item in self.taxonomy.classes:
            number = int(item["class_number"])
            if not self._glob_matches(record.relative_path, item["target_file_globs"]):
                continue
            matches: list[dict[str, Any]] = []
            for term in item["negative_evidence_searches"]:
                term = str(term)
                if term.startswith("*."):
                    searches += 1
                    if fnmatch.fnmatch(record.relative_path.lower(), f"*{term[1:].lower()}"):
                        matches.append({"file": record.relative_path, "line": None, "indicator": term})
            if text is not None:
                for term, pattern in self.patterns[number]:
                    searches += 1
                    match = pattern.search(text)
                    if match:
                        matches.append(
                            {
                                "file": record.relative_path,
                                "line": text.count("\n", 0, match.start()) + 1,
                                "indicator": term,
                            }
                        )
            if matches:
                unique = {(value["file"], value["line"], value["indicator"]): value for value in matches}
                results[str(number)] = tuple(
                    unique[key] for key in sorted(unique, key=lambda key: (key[0], key[1] or 0, key[2]))
                )
        return results, searches


def build_negative_evidence(
    taxonomy: TaxonomyBundle,
    decisions: list[dict[str, Any]],
    skipped: list[SkippedEntry],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for decision in decisions:
        status = str(decision["status"])
        artifacts.append(
            {
                "class_number": decision["class_number"],
                "class_name": decision["class_name"],
                "status": status,
                "searched": decision["search_patterns"],
                "searched_carrier_types": decision["searched_carrier_types"],
                "files_considered": decision["files_inspected"]["count"],
                "matches": decision["positive_matches"],
                "skipped_security_relevant_files": decision["skipped_files_affecting_confidence"],
                "negative_search_summary": decision["negative_search_summary"],
                "confidence": "HIGH"
                if status == "NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE"
                else "LOW"
                if status == "UNRESOLVED"
                else "MEDIUM",
            }
        )
    return artifacts
