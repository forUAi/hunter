"""Auditable directory exclusions that never suppress tests or security carriers."""

from __future__ import annotations

DEFAULT_IGNORED_DIRECTORIES: dict[str, str] = {
    ".git": "git metadata directory",
    "node_modules": "third-party dependency directory",
    "target": "generated build output directory",
    "build": "generated build output directory",
    "dist": "generated distribution directory",
    "coverage": "generated coverage output directory",
    "vendor": "vendored dependency directory",
    ".venv": "Python virtual environment",
    "venv": "Python virtual environment",
    "__pycache__": "Python bytecode cache",
    ".next": "generated Next.js output directory",
    ".gradle": "Gradle cache directory",
}


def ignored_directory_reason(name: str) -> str | None:
    return DEFAULT_IGNORED_DIRECTORIES.get(name)
