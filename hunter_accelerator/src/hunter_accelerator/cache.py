"""Content-addressed per-file cache outside the untrusted target repository."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .hashing import stable_json_hash
from .models import FileAnalysis, FileRecord

CACHE_SCHEMA_VERSION = "hunter-accelerator-file-cache-1"


class AnalysisCache:
    def __init__(
        self,
        root: Path,
        repository_path: str,
        taxonomy_version: str,
        accelerator_version: str,
        configuration_version: str,
        commit_sha: str | None,
        working_tree_state: str,
        enabled: bool,
    ) -> None:
        self.root = root
        self.repository_path = repository_path
        self.taxonomy_version = taxonomy_version
        self.accelerator_version = accelerator_version
        self.configuration_version = configuration_version
        self.commit_sha = commit_sha
        self.working_tree_state = working_tree_state
        self.enabled = enabled

    def _key(self, record: FileRecord) -> str:
        return stable_json_hash(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "target_repository_absolute_path": self.repository_path,
                "relative_path": record.relative_path,
                "working_tree_file_hash": record.content_hash,
                "commit_sha": self.commit_sha,
                "working_tree_state": self.working_tree_state,
                "taxonomy_version": self.taxonomy_version,
                "accelerator_version": self.accelerator_version,
                "configuration_version": self.configuration_version,
            }
        )

    def _path(self, record: FileRecord) -> Path:
        key = self._key(record)
        return self.root / "files" / key[:2] / f"{key}.json"

    def load(self, record: FileRecord) -> FileAnalysis | None:
        if not self.enabled:
            return None
        path = self._path(record)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or value.get("schema") != CACHE_SCHEMA_VERSION:
                return None
            analysis = value.get("analysis")
            if not isinstance(analysis, dict):
                return None
            return FileAnalysis.from_json(analysis)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return None

    def store(self, record: FileRecord, analysis: FileAnalysis) -> None:
        if not self.enabled:
            return
        path = self._path(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {"schema": CACHE_SCHEMA_VERSION, "analysis": analysis.as_json()}
        descriptor, temporary_name = tempfile.mkstemp(prefix=".cache-", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
            os.replace(temporary_name, path)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
