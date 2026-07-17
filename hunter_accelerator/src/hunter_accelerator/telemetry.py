"""Local runtime telemetry with no network or model integration."""

from __future__ import annotations

import time
from contextlib import contextmanager
from collections.abc import Iterator

from .models import ScanMetrics


class Telemetry:
    def __init__(self) -> None:
        self.metrics = ScanMetrics(start_monotonic=time.monotonic())

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        started = time.monotonic()
        try:
            yield
        finally:
            self.metrics.phase_seconds[name] = round(time.monotonic() - started, 6)

    def as_json(self) -> dict[str, object]:
        total = round(time.monotonic() - self.metrics.start_monotonic, 6)
        return {
            "total_runtime_seconds": total,
            "inventory_runtime_seconds": self.metrics.phase_seconds.get("inventory", 0.0),
            "carrier_analysis_runtime_seconds": self.metrics.phase_seconds.get("carrier_analysis", 0.0),
            "applicability_runtime_seconds": self.metrics.phase_seconds.get("applicability", 0.0),
            "matcher_generation_runtime_seconds": self.metrics.phase_seconds.get("matcher_generation", 0.0),
            "logic_target_runtime_seconds": self.metrics.phase_seconds.get("logic_targets", 0.0),
            "phase_seconds": dict(sorted(self.metrics.phase_seconds.items())),
            "files_scanned": self.metrics.files_scanned,
            "bytes_scanned": self.metrics.bytes_scanned,
            "cache_hits": self.metrics.cache_hits,
            "cache_misses": self.metrics.cache_misses,
            "regex_searches": self.metrics.regex_searches,
            "coverage_gaps": self.metrics.coverage_gaps,
        }
