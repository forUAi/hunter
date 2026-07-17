"""Stable content and identifier hashing helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_json_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return sha256_bytes(encoded)


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    digest = sha256_bytes("\x1f".join(str(part) for part in parts).encode("utf-8"))[:length]
    return f"{prefix}-{digest}"
