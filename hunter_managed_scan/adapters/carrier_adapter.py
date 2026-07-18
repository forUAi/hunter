"""Managed-scan filtering for class-specific deterministic carrier leads."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

GENERIC_CARRIERS = frozenset({"source code", "configuration", "secret-bearing configuration", "dependency manifest"})
LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "gemfile.lock",
        "packages.lock.json",
        "podfile.lock",
        "pubspec.lock",
    }
)


def _is_lockfile(path: str) -> bool:
    return PurePosixPath(path).name.lower() in LOCKFILE_NAMES


def class_specific_evidence(
    class_number: int,
    carrier_inventory: list[dict[str, Any]],
    applicability_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in carrier_inventory:
        if class_number not in [int(value) for value in item.get("classes_activated", [])]:
            continue
        carrier_type = str(item.get("carrier_type", ""))
        file = str(item.get("file", ""))
        if carrier_type in GENERIC_CARRIERS:
            continue
        if class_number in {64, 65} and _is_lockfile(file):
            continue
        evidence.append(item)
    for item in applicability_entry.get("positive_matches", []):
        if item.get("carrier_type") != "class-specific search":
            continue
        file = str(item.get("file", ""))
        if class_number in {64, 65} and _is_lockfile(file):
            continue
        evidence.append(item)
    unique = {
        (
            str(item.get("carrier_type", "")),
            str(item.get("file", "")),
            item.get("line"),
            str(item.get("evidence", "")),
        ): item
        for item in evidence
    }
    return [unique[key] for key in sorted(unique, key=lambda key: (key[0], key[1], key[2] or 0, key[3]))]


def candidate_files(evidence: list[dict[str, Any]]) -> list[str]:
    return sorted({str(item["file"]) for item in evidence if item.get("file") and item.get("file") != ".git"})


def security_surfaces(evidence: list[dict[str, Any]]) -> list[str]:
    return sorted({str(item.get("carrier_type")) for item in evidence if item.get("carrier_type")})
