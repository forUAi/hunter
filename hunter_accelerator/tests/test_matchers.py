from __future__ import annotations

import re
import unittest

from helpers import FIXTURES, run_repository


class MatcherTests(unittest.TestCase):
    def test_every_applicable_class_has_matcher_or_handoff(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "mixed_repository")
        matchers = artifacts["mandatory-matchers.json"]
        covered = {item["class_number"] for item in matchers}
        for decision in artifacts["category-applicability.json"]:
            if decision["status"] in {"ALWAYS_APPLICABLE", "APPLICABLE"} and decision["class_number"] != 58:
                self.assertIn(decision["class_number"], covered)
        for matcher in matchers:
            self.assertIn("class_number", matcher)
            self.assertIn("owasp", matcher)
            self.assertFalse(matcher["is_finding"])
            self.assertNotIn("severity", matcher)
            re.compile(matcher["regex"])

    def test_absence_and_non_source_matchers_are_explicit(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "infrastructure")
        matchers = artifacts["mandatory-matchers.json"]
        absence = {item["class_number"] for item in matchers if item["absence_detection"]}
        self.assertTrue({10, 59, 60, 62}.issubset(absence))
        hydra = [item for item in matchers if item["class_number"] == 63]
        self.assertEqual(set(range(22, 28)), {item["hydra_check_id"] for item in hydra if "hydra_check_id" in item})
        self.assertTrue(any("**/.github/workflows/*" in item["file_globs"] for item in hydra))

    def test_mobile_and_prompt_matcher_coverage(self) -> None:
        _status, mobile = run_repository(FIXTURES / "mobile")
        mobile_matchers = [item for item in mobile["mandatory-matchers.json"] if item["class_number"] == 64]
        self.assertEqual({f"M{number}" for number in range(1, 11)}, {item["mobile_category"]["id"] for item in mobile_matchers if "mobile_category" in item})
        _status, ai = run_repository(FIXTURES / "llm_agentic")
        for number in range(66, 86):
            specs = [item for item in ai["mandatory-matchers.json"] if item["class_number"] == number]
            self.assertTrue(specs)
            self.assertTrue(any("**/SKILL.md" in item["file_globs"] for item in specs))


if __name__ == "__main__":
    unittest.main()
