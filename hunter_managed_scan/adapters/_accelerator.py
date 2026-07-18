"""Resolve the existing source-layout package without copying its implementation."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACCELERATOR_SOURCE = REPOSITORY_ROOT / "hunter_accelerator" / "src"
CANONICAL_TAXONOMY = REPOSITORY_ROOT / "hunter_accelerator" / "taxonomy" / "hunter_all_85.json"

if str(ACCELERATOR_SOURCE) not in sys.path:
    sys.path.insert(0, str(ACCELERATOR_SOURCE))
