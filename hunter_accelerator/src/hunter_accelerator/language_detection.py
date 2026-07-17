"""Path-based language detection; target code is never imported or executed."""

from __future__ import annotations

from pathlib import PurePosixPath

EXTENSION_LANGUAGES = {
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".go": "Go",
    ".cs": "C#",
    ".fs": "F#",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".php": "PHP",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".tf": "HCL",
    ".bicep": "Bicep",
}

SOURCE_EXTENSIONS = frozenset(EXTENSION_LANGUAGES)


def detect_languages(relative_path: str) -> tuple[str, ...]:
    path = PurePosixPath(relative_path)
    language = EXTENSION_LANGUAGES.get(path.suffix.lower())
    return (language,) if language else ()
