"""Runtime configuration with no environment-dependent package requirements."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import __version__

CONFIGURATION_VERSION = "phase1-config-1"
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_OUTPUT_DIR = Path("/tmp/hunter-accelerator")
DEFAULT_CACHE_DIR = Path("/tmp/hunter-accelerator-cache")


@dataclass(frozen=True)
class AcceleratorConfiguration:
    target_repo: Path
    output_dir: Path
    taxonomy_path: Path
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    cache_dir: Path = DEFAULT_CACHE_DIR
    use_cache: bool = True
    strict: bool = False
    summary_only: bool = False
    accelerator_version: str = __version__
    configuration_version: str = CONFIGURATION_VERSION

    def validate_numbers(self) -> None:
        if self.max_file_size <= 0:
            raise ValueError("max-file-size must be positive")
        if self.max_total_bytes <= 0:
            raise ValueError("max-total-bytes must be positive")
        if self.max_file_size > self.max_total_bytes:
            raise ValueError("max-file-size cannot exceed max-total-bytes")
