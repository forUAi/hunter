"""Reject obvious plaintext credentials from child-produced artifacts."""

from __future__ import annotations

import json
import re
from typing import Any

from hunter_managed_scan.errors import VerificationError

OBVIOUS_SECRETS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{24,}\b"),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
)
ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?([^\s,'\";}]{8,})"
)
SAFE_MARKERS = ("<redacted>", "redacted", "example", "dummy", "inert", "test-only", "placeholder")


def verify_no_plaintext_secrets(value: Any) -> None:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True)
    for pattern in OBVIOUS_SECRETS:
        if pattern.search(text):
            raise VerificationError("child artifact contains an obvious plaintext credential")
    for match in ASSIGNMENT.finditer(text):
        candidate = match.group(1).lower()
        if not any(marker in candidate for marker in SAFE_MARKERS):
            raise VerificationError("child artifact contains an unredacted credential assignment")
