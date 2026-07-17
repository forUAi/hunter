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
            "java_spring": {"Spring", "Spring WebFlux"},
            "java_vertx": {"Vert.x"},
            "infrastructure": set(),
            "github_actions": set(),
            "mobile": set(),
            "llm_agentic": set(),
            "mixed_repository": {"Express"},
        }
        for name, frameworks in expectations.items():
            with self.subTest(fixture=name):
                target = FIXTURES / name
                before = tree_digest(target)
                status, artifacts = run_repository(target)
                self.assertIn(status, {"COMPLETE", "PARTIAL"})
                self.assertEqual(85, len(artifacts["category-applicability.json"]))
                self.assertTrue(frameworks.issubset(set(artifacts["repository-profile.json"]["frameworks"])))
                self.assertEqual(before, tree_digest(target))
                serialized = json.dumps(artifacts["mandatory-matchers.json"])
                self.assertNotIn('"severity"', serialized)
                self.assertNotIn('"cvss"', serialized)

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
            self.assertIn(completed.returncode, {0, 2})
            self.assertIn("Hunter Accelerator:", completed.stdout)
            self.assertTrue((Path(output_name) / "manifest.json").exists())
            self.assertTrue((Path(output_name) / "file-inventory.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
