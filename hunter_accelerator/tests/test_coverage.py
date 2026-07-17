from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import run_repository


class CoverageTests(unittest.TestCase):
    def test_security_relevant_skip_is_a_first_class_gap(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "security.py").write_text("def authorize():\n    return True\n" * 20, encoding="utf-8")
            status, artifacts = run_repository(root, max_file_size=16, max_total_bytes=1024)
            self.assertEqual("PARTIAL", status)
            conditions = {item["condition"] for item in artifacts["coverage-gaps.json"]}
            self.assertIn("security_relevant_file_skipped", conditions)
            self.assertIn("unresolved_applicability", conditions)

    def test_class_58_is_explicit_handoff_not_phase1_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
            _status, artifacts = run_repository(root)
            decision = artifacts["category-applicability.json"][57]
            self.assertTrue(decision["downstream_handoff"])
            self.assertFalse(any(item["class_number"] == 58 for item in artifacts["mandatory-matchers.json"]))
            self.assertFalse(any(58 in item["affected_classes"] for item in artifacts["coverage-gaps.json"] if item["condition"] == "applicable_class_without_matcher"))


if __name__ == "__main__":
    unittest.main()
