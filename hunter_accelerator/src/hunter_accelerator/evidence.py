"""Compact evidence helpers that never expose likely secret values."""

from __future__ import annotations

import re

SECRET_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)
BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def redact_text(value: str, limit: int = 240) -> str:
    """Redact values while retaining variable names and a bounded diagnostic shape."""
    cleaned = value.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    cleaned = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", cleaned)
    cleaned = BEARER.sub(lambda match: f"{match.group(1)} <redacted>", cleaned)
    cleaned = PRIVATE_KEY.sub("<private-key-marker>", cleaned)
    return cleaned[:limit]


def indicator_evidence(label: str) -> str:
    """Describe what matched without copying untrusted repository content."""
    return f"matched indicator: {redact_text(label, 120)}"
