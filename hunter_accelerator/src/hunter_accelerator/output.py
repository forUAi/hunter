"""Atomic, deterministically ordered artifact writing and output validation."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import OutputValidationError
from .hashing import sha256_bytes

ARTIFACT_NAMES = (
    "manifest.json",
    "summary.json",
    "repository-profile.json",
    "file-inventory.jsonl",
    "skipped-files.json",
    "carrier-inventory.json",
    "category-applicability.json",
    "negative-evidence.json",
    "mandatory-matchers.json",
    "logic-targets.json",
    "unsupported-constructs.json",
    "coverage-gaps.json",
    "telemetry.json",
    "errors.json",
)


def validate_artifacts(artifacts: dict[str, Any]) -> None:
    decisions = artifacts.get("category-applicability.json")
    if not isinstance(decisions, list) or [item.get("class_number") for item in decisions] != list(range(1, 86)):
        raise OutputValidationError("category applicability must contain ordered classes 1 through 85")
    valid_statuses = {"ALWAYS_APPLICABLE", "APPLICABLE", "NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE", "UNRESOLVED"}
    if any(item.get("status") not in valid_statuses for item in decisions):
        raise OutputValidationError("category applicability contains an invalid status")
    matchers = artifacts.get("mandatory-matchers.json")
    if not isinstance(matchers, list):
        raise OutputValidationError("mandatory matchers must be a list")
    prohibited = {"severity", "cvss", "finding", "vulnerable", "remediation"}
    for matcher in matchers:
        if not {"matcher_id", "class_number", "class_name", "owasp", "file_globs", "regex", "mandatory"}.issubset(matcher):
            raise OutputValidationError("mandatory matcher is missing required fields")
        if prohibited & set(matcher):
            raise OutputValidationError("Phase 1 matcher contains a prohibited finding-decision field")
        if matcher.get("is_finding") is not False:
            raise OutputValidationError("Phase 1 matcher must explicitly declare is_finding=false")
    gaps = artifacts.get("coverage-gaps.json")
    if not isinstance(gaps, list):
        raise OutputValidationError("coverage gaps must be a list")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_artifacts(output_dir: Path, artifacts: dict[str, Any], inventory_lines: list[dict[str, Any]]) -> dict[str, str]:
    validate_artifacts(artifacts)
    output_dir.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for name in ARTIFACT_NAMES:
        if name == "manifest.json":
            continue
        if name == "file-inventory.jsonl":
            data = b"".join(
                (json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                for item in inventory_lines
            )
        else:
            if name not in artifacts:
                raise OutputValidationError(f"missing required output artifact: {name}")
            data = _json_bytes(artifacts[name])
        _atomic_write(output_dir / name, data)
        hashes[name] = sha256_bytes(data)
    return hashes


def write_manifest(output_dir: Path, manifest: dict[str, Any]) -> str:
    data = _json_bytes(manifest)
    _atomic_write(output_dir / "manifest.json", data)
    return sha256_bytes(data)
