from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES, run_repository


class CacheTests(unittest.TestCase):
    def test_unchanged_files_hit_cache_and_changed_file_invalidates_only_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hunter-cache-test-") as cache_name, tempfile.TemporaryDirectory(prefix="hunter-target-test-") as target_name:
            target = Path(target_name)
            for source in (FIXTURES / "mixed_repository").rglob("*"):
                if source.is_file():
                    destination = target / source.relative_to(FIXTURES / "mixed_repository")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
            cache = Path(cache_name)
            _status, first = run_repository(target, use_cache=True, cache_dir=cache)
            self.assertEqual("MISS", first["summary.json"]["cache_status"])
            _status, second = run_repository(target, use_cache=True, cache_dir=cache)
            self.assertEqual("HIT", second["summary.json"]["cache_status"])
            (target / "src" / "server.ts").write_text("export const changed = true;", encoding="utf-8")
            _status, third = run_repository(target, use_cache=True, cache_dir=cache)
            self.assertEqual("PARTIAL_HIT", third["summary.json"]["cache_status"])
            self.assertEqual(1, third["telemetry.json"]["cache_misses"])


if __name__ == "__main__":
    unittest.main()
