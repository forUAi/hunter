"""Read-only repository boundary and safe Git metadata inspection."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .errors import WorkspaceSafetyError
from .hashing import stable_id
from .models import RepositoryInfo


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class RepositoryWorkspace:
    def __init__(self, target_repo: Path, output_dir: Path, cache_dir: Path) -> None:
        try:
            self.root = target_repo.expanduser().resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise WorkspaceSafetyError("target repository does not exist or cannot be resolved") from exc
        if not self.root.is_dir():
            raise WorkspaceSafetyError("target repository must be an existing directory")
        self.output_dir = output_dir.expanduser().resolve(strict=False)
        self.cache_dir = cache_dir.expanduser().resolve(strict=False)
        if _is_within(self.output_dir, self.root):
            raise WorkspaceSafetyError("output directory must be outside the target repository")
        if _is_within(self.cache_dir, self.root):
            raise WorkspaceSafetyError("cache directory must be outside the target repository")

    def relative_path(self, candidate: Path) -> str:
        resolved = candidate.resolve(strict=True)
        if not _is_within(resolved, self.root):
            raise WorkspaceSafetyError("path resolves outside target repository")
        return resolved.relative_to(self.root).as_posix()

    def _git(self, *arguments: str) -> tuple[int, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
            }
        )
        command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *arguments]
        try:
            completed = subprocess.run(
                command,
                cwd=self.root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return 1, ""
        return completed.returncode, completed.stdout.strip()

    def repository_info(self) -> RepositoryInfo:
        git_entry = self.root / ".git"
        # Never discover or read a parent repository. Worktree gitfiles and symlinked
        # Git metadata may point outside the target boundary, so they are not followed.
        try:
            if not git_entry.exists() or git_entry.is_symlink() or not git_entry.is_dir():
                raise OSError
            if not _is_within(git_entry.resolve(strict=True), self.root):
                raise OSError
        except OSError:
            return RepositoryInfo(
                repository_id=stable_id("repo", str(self.root), length=24),
                name=self.root.name,
                absolute_path=str(self.root),
                commit_sha=None,
                working_tree_state="not_git",
                has_git_history=False,
            )
        inside_code, inside = self._git("rev-parse", "--is-inside-work-tree")
        is_git = inside_code == 0 and inside == "true"
        commit: str | None = None
        state = "not_git"
        if is_git:
            commit_code, commit_value = self._git("rev-parse", "HEAD")
            if commit_code == 0 and commit_value:
                commit = commit_value.splitlines()[0]
            status_code, status_value = self._git("status", "--porcelain=v1", "--untracked-files=all")
            state = "dirty" if status_code == 0 and status_value else "clean" if status_code == 0 else "unknown"
        return RepositoryInfo(
            repository_id=stable_id("repo", str(self.root), length=24),
            name=self.root.name,
            absolute_path=str(self.root),
            commit_sha=commit,
            working_tree_state=state,
            has_git_history=bool(commit),
        )
