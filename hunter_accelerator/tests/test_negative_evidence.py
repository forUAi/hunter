from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import run_repository


class NegativeEvidenceTests(unittest.TestCase):
    def test_na_records_executed_patterns_and_empty_matches(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "notes.txt").write_text("no application carriers", encoding="utf-8")
            _status, artifacts = run_repository(root)
            evidence = {item["class_number"]: item for item in artifacts["negative-evidence.json"]}[13]
            self.assertEqual("NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE", evidence["status"])
            self.assertIn("RestTemplate", evidence["searched"])
            self.assertEqual([], evidence["matches"])
            self.assertEqual([], evidence["skipped_security_relevant_files"])
            self.assertEqual("HIGH", evidence["confidence"])


if __name__ == "__main__":
    unittest.main()
