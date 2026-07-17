from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES, ROOT, run_repository, tree_digest


class EndToEndTests(unittest.TestCase):
    def test_required_fixtures_produce_phase1_artifacts_without_findings(self) -> None:
        expectations = {
            "java_spring": {"frameworks": {"Spring", "Spring WebFlux"}, "minimum_matchers": 74, "logic_targets": 2, "coverage_gaps": 0},
            "java_vertx": {"frameworks": {"Vert.x"}, "minimum_matchers": 66, "logic_targets": 5, "coverage_gaps": 0},
            "infrastructure": {"frameworks": set(), "minimum_matchers": 54, "logic_targets": 0, "coverage_gaps": 0},
            "github_actions": {"frameworks": set(), "minimum_matchers": 43, "logic_targets": 0, "coverage_gaps": 0},
            "mobile": {"frameworks": set(), "minimum_matchers": 76, "logic_targets": 0, "coverage_gaps": 0},
            "llm_agentic": {"frameworks": set(), "minimum_matchers": 74, "logic_targets": 1, "coverage_gaps": 0},
            "mixed_repository": {"frameworks": {"Express"}, "minimum_matchers": 74, "logic_targets": 1, "coverage_gaps": 0},
        }
        stable_artifacts = (
            "repository-profile.json",
            "file-inventory.jsonl",
            "skipped-files.json",
            "carrier-inventory.json",
            "category-applicability.json",
            "negative-evidence.json",
            "mandatory-matchers.json",
            "logic-targets.json",
            "unsupported-constructs.json",
            "coverage-gaps.json",
            "errors.json",
        )
        for name, expected in expectations.items():
            with self.subTest(fixture=name):
                target = FIXTURES / name
                before = tree_digest(target)
                status, artifacts = run_repository(target)
                repeated_status, repeated = run_repository(target)
                self.assertEqual("COMPLETE", status)
                self.assertEqual(status, repeated_status)
                self.assertEqual(85, len(artifacts["category-applicability.json"]))
                self.assertEqual(list(range(1, 86)), [item["class_number"] for item in artifacts["category-applicability.json"]])
                self.assertTrue(expected["frameworks"].issubset(set(artifacts["repository-profile.json"]["frameworks"])))
                self.assertGreaterEqual(len(artifacts["mandatory-matchers.json"]), expected["minimum_matchers"])
                self.assertEqual(expected["logic_targets"], len(artifacts["logic-targets.json"]))
                self.assertEqual(expected["coverage_gaps"], len(artifacts["coverage-gaps.json"]))
                self.assertEqual(str(target.resolve()), artifacts["manifest.json"]["target_repository"])
                self.assertIn("commit_sha", artifacts["manifest.json"])
                self.assertIsNone(artifacts["manifest.json"]["commit_sha"])
                self.assertEqual(before, tree_digest(target))
                for artifact_name in stable_artifacts:
                    self.assertEqual(artifacts[artifact_name], repeated[artifact_name], artifact_name)
                serialized = json.dumps(artifacts["mandatory-matchers.json"])
                self.assertNotIn('"severity"', serialized)
                self.assertNotIn('"cvss"', serialized)
                self.assertNotIn("findings.json", artifacts)
                self.assertTrue(all(item["is_finding"] is False for item in artifacts["mandatory-matchers.json"]))

    def test_direct_script_interface_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as output_name, tempfile.TemporaryDirectory() as cache_name:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "devin_prepare.py"),
                    "--target-repo",
                    str(FIXTURES / "mixed_repository"),
                    "--output-dir",
                    output_name,
                    "--cache-dir",
                    cache_name,
                    "--no-cache",
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(0, completed.returncode)
            self.assertIn("Hunter Accelerator: COMPLETE", completed.stdout)
            self.assertTrue((Path(output_name) / "manifest.json").exists())
            self.assertTrue((Path(output_name) / "file-inventory.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
