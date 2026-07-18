"""Read-only target snapshots used before, during, and after every scan phase."""

from __future__ import annotations

from pathlib import Path

from hunter_managed_scan.adapters import _accelerator  # noqa: F401
from hunter_accelerator.hashing import sha256_bytes
from hunter_accelerator.workspace import RepositoryWorkspace

from hunter_managed_scan.errors import OperationalError, TargetModifiedError
from hunter_managed_scan.models.manifest import TargetSnapshot


def capture_target_snapshot(target_repo_path: Path, safe_output_root: Path) -> TargetSnapshot:
    workspace = RepositoryWorkspace(
        target_repo_path,
        safe_output_root / ".target-guard-output",
        safe_output_root / ".target-guard-cache",
    )
    repository = workspace.repository_info()
    if repository.git_metadata_status != "resolved" or not repository.commit_sha:
        raise OperationalError("target repository Git metadata and commit must resolve before scanning")
    status_code, status = workspace._git("status", "--porcelain=v1", "--untracked-files=all")
    diff_code, diff = workspace._git("diff", "--binary", "--no-ext-diff", "HEAD")
    if status_code != 0 or diff_code != 0:
        raise OperationalError("target repository status or diff could not be read safely")
    return TargetSnapshot(
        commit_sha=repository.commit_sha,
        status_porcelain=status,
        diff_sha256=sha256_bytes(diff.encode("utf-8")),
    )


def require_initial_target(target_repo_path: Path, safe_output_root: Path, expected_commit: str) -> TargetSnapshot:
    snapshot = capture_target_snapshot(target_repo_path, safe_output_root)
    if snapshot.commit_sha != expected_commit:
        raise OperationalError(
            f"target commit mismatch: expected {expected_commit}, resolved {snapshot.commit_sha}"
        )
    if snapshot.status_porcelain:
        raise OperationalError("target repository must begin with a clean working tree")
    return snapshot


def require_target_unchanged(
    target_repo_path: Path,
    safe_output_root: Path,
    initial: TargetSnapshot,
) -> TargetSnapshot:
    current = capture_target_snapshot(target_repo_path, safe_output_root)
    if current != initial:
        raise TargetModifiedError("target repository changed after the immutable scan snapshot")
    return current
