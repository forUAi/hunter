"""Read-only repository boundary and safe Git metadata inspection."""

from __future__ import annotations

import os
import stat as stat_module
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
        try:
            git_stat = git_entry.lstat()
        except FileNotFoundError:
            return RepositoryInfo(
                repository_id=stable_id("repo", str(self.root), length=24),
                name=self.root.name,
                absolute_path=str(self.root),
                commit_sha=None,
                working_tree_state="not_git",
                has_git_history=False,
                git_metadata_status="not_git",
            )
        except OSError:
            return self._unresolved_repository_info("unable to inspect the .git metadata entry")

        # A regular .git file is the standard representation for worktrees and
        # submodules. Let the constrained Git wrapper resolve it; never parse or
        # follow its path directly. Symlinks and special files remain unresolved.
        if stat_module.S_ISLNK(git_stat.st_mode):
            return self._unresolved_repository_info("the .git metadata entry is a symlink")
        if not (stat_module.S_ISDIR(git_stat.st_mode) or stat_module.S_ISREG(git_stat.st_mode)):
            return self._unresolved_repository_info("the .git metadata entry is not a directory or gitfile")
        if stat_module.S_ISDIR(git_stat.st_mode):
            try:
                if not _is_within(git_entry.resolve(strict=True), self.root):
                    return self._unresolved_repository_info("the .git directory resolves outside the target repository")
            except OSError:
                return self._unresolved_repository_info("the .git directory cannot be safely resolved")

        inside_code, inside = self._git("rev-parse", "--is-inside-work-tree")
        is_git = inside_code == 0 and inside == "true"
        if not is_git:
            return self._unresolved_repository_info("Git could not resolve the repository metadata")

        top_level_code, top_level_value = self._git("rev-parse", "--show-toplevel")
        try:
            top_level = Path(top_level_value).resolve(strict=True) if top_level_code == 0 and top_level_value else None
        except OSError:
            top_level = None
        if top_level != self.root:
            return self._unresolved_repository_info("Git resolved a work tree other than the target repository")

        commit_code, commit_value = self._git("rev-parse", "--verify", "HEAD^{commit}")
        if commit_code != 0 or not commit_value:
            return self._unresolved_repository_info("Git history is present but the current commit cannot be resolved")
        commit = commit_value.splitlines()[0]
        status_code, status_value = self._git("status", "--porcelain=v1", "--untracked-files=all")
        if status_code != 0:
            return self._unresolved_repository_info("Git working-tree status cannot be resolved")
        state = "dirty" if status_value else "clean"
        return RepositoryInfo(
            repository_id=stable_id("repo", str(self.root), length=24),
            name=self.root.name,
            absolute_path=str(self.root),
            commit_sha=commit,
            working_tree_state=state,
            has_git_history=True,
            git_metadata_status="resolved",
        )

    def _unresolved_repository_info(self, reason: str) -> RepositoryInfo:
        return RepositoryInfo(
            repository_id=stable_id("repo", str(self.root), length=24),
            name=self.root.name,
            absolute_path=str(self.root),
            commit_sha=None,
            working_tree_state="unknown",
            has_git_history=False,
            git_metadata_status="unresolved",
            git_metadata_reason=reason,
        )
