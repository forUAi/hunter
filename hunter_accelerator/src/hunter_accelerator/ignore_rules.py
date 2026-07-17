"""Auditable exclusions limited to caches, metadata, and installed dependencies."""

from __future__ import annotations

DEFAULT_IGNORED_DIRECTORIES: dict[str, str] = {
    ".git": "git metadata directory",
    "node_modules": "third-party dependency directory",
    "coverage": "generated coverage output directory",
    "htmlcov": "generated coverage output directory",
    ".nyc_output": "generated coverage output directory",
    ".venv": "Python virtual environment",
    "venv": "Python virtual environment",
    "__pycache__": "Python bytecode cache",
    ".gradle": "Gradle cache directory",
}


def ignored_directory_reason(name: str) -> str | None:
    if "pycache" in name.lower():
        return "Python bytecode cache"
    return DEFAULT_IGNORED_DIRECTORIES.get(name)
