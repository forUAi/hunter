from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES, run_repository


class ApplicabilityTests(unittest.TestCase):
    def test_always_applicable_classes_never_become_na(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.txt").write_text("empty fixture", encoding="utf-8")
            _status, artifacts = run_repository(root)
            by_number = {item["class_number"]: item for item in artifacts["category-applicability.json"]}
            for number in (10, 11, 22, 25, 38, 43, 46, 49, 50, 55, 56, 57):
                self.assertEqual("ALWAYS_APPLICABLE", by_number[number]["status"])

    def test_prompt_content_activates_all_ai_classes(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "llm_agentic")
        by_number = {item["class_number"]: item for item in artifacts["category-applicability.json"]}
        self.assertTrue(all(by_number[number]["status"] == "APPLICABLE" for number in range(66, 86)))

    def test_helm_and_workflow_activate_platform_classes(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "infrastructure")
        by_number = {item["class_number"]: item for item in artifacts["category-applicability.json"]}
        for number in (59, 60, 61, 62, 63):
            self.assertEqual("APPLICABLE", by_number[number]["status"])

    def test_missing_carriers_have_negative_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "notes.txt").write_text("plain text", encoding="utf-8")
            _status, artifacts = run_repository(root)
            decision = artifacts["category-applicability.json"][12]
            self.assertEqual(13, decision["class_number"])
            self.assertEqual("NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE", decision["status"])
            self.assertIn("zero relevant carriers", decision["negative_search_summary"])

    def test_skipped_relevant_file_forces_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "client.py").write_text("requests.get(url)" * 100, encoding="utf-8")
            status, artifacts = run_repository(root, max_file_size=32, max_total_bytes=4096)
            self.assertEqual("PARTIAL", status)
            by_number = {item["class_number"]: item for item in artifacts["category-applicability.json"]}
            self.assertEqual("UNRESOLVED", by_number[13]["status"])


if __name__ == "__main__":
    unittest.main()
