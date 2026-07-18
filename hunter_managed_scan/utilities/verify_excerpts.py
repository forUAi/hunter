"""Mechanical file, line, excerpt, and SHA-256 verification."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from hunter_managed_scan.adapters import _accelerator  # noqa: F401
from hunter_accelerator.hashing import sha256_bytes

from hunter_managed_scan.errors import VerificationError


def _resolve_target_file(target_repo_path: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise VerificationError(f"unsafe evidence path: {relative_path}")
    root = target_repo_path.resolve(strict=True)
    try:
        candidate = (root / Path(*pure.parts)).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise VerificationError(f"evidence file does not resolve inside target: {relative_path}") from exc
    if not candidate.is_file():
        raise VerificationError(f"evidence path is not a file: {relative_path}")
    return candidate


def source_excerpt(target_repo_path: Path, relative_path: str, start_line: int, end_line: int) -> str:
    if start_line < 1 or end_line < start_line:
        raise VerificationError(f"invalid evidence line range for {relative_path}: {start_line}-{end_line}")
    path = _resolve_target_file(target_repo_path, relative_path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError(f"evidence file is not readable UTF-8 text: {relative_path}") from exc
    if end_line > len(lines):
        raise VerificationError(f"evidence line range exceeds {relative_path}: {start_line}-{end_line}")
    return "\n".join(lines[start_line - 1 : end_line])


def verify_affected_instance(target_repo_path: Path, instance: dict[str, Any]) -> None:
    relative_path = str(instance["file"])
    excerpt = source_excerpt(
        target_repo_path,
        relative_path,
        int(instance["start_line"]),
        int(instance["end_line"]),
    )
    if excerpt != instance["excerpt"]:
        raise VerificationError(f"excerpt does not match target source: {relative_path}")
    expected_hash = sha256_bytes(excerpt.encode("utf-8"))
    if instance["excerpt_sha256"] != expected_hash:
        raise VerificationError(f"excerpt hash does not match target source: {relative_path}")


def verify_finding_excerpts(target_repo_path: Path, finding: dict[str, Any]) -> None:
    for instance in finding.get("affected_instances", []):
        verify_affected_instance(target_repo_path, instance)
