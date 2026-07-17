from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, run_repository, tree_digest


class GeneratedDirectoryTests(unittest.TestCase):
    def test_security_carriers_in_generated_and_vendor_directories_are_inspected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            files = {
                "dist/system.prompt": "system prompt: use the tool_result with openai and tool_call",
                "build/routes.ts": "app.post('/transfer', async (req, res) => { await save(req.body); });",
                "target/application.yml": "api_secret: generated-only-secret\n",
                "target/infrastructure/main.tf": 'provider "aws" {}\nresource "aws_s3_bucket" "private" {}\n',
                ".next/server/config.json": '{"system_prompt":"agent instruction"}',
                "vendor/security.py": "def authorize(user):\n    return permission_required(user)\n",
            }
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            before = tree_digest(root)

            status, artifacts = run_repository(root)

            self.assertEqual("COMPLETE", status)
            inventory = {item["relative_path"]: item for item in artifacts["file-inventory.jsonl"]}
            self.assertEqual(set(files), set(inventory))
            for relative in ("dist/system.prompt", "build/routes.ts", "target/application.yml", "target/infrastructure/main.tf", ".next/server/config.json"):
                self.assertTrue(inventory[relative]["generated"], relative)
                self.assertFalse(inventory[relative]["vendor_derived"], relative)
            self.assertTrue(inventory["vendor/security.py"]["vendor_derived"])
            self.assertFalse(inventory["vendor/security.py"]["generated"])

            carriers = {(item["carrier_type"], item["file"]) for item in artifacts["carrier-inventory.json"]}
            self.assertIn(("prompt or instruction", "dist/system.prompt"), carriers)
            self.assertIn(("HTTP/API route", "build/routes.ts"), carriers)
            self.assertIn(("secret-bearing configuration", "target/application.yml"), carriers)
            self.assertIn(("Terraform/IaC", "target/infrastructure/main.tf"), carriers)
            self.assertEqual([], artifacts["coverage-gaps.json"])
            self.assertEqual(before, tree_digest(root))

    def test_generated_carrier_limit_is_partial_and_strict_converts_to_failed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            prompt = root / "dist" / "system.prompt"
            prompt.parent.mkdir(parents=True)
            prompt.write_text("system prompt openai tool_call " * 20, encoding="utf-8")

            status, artifacts = run_repository(root, max_file_size=32, max_total_bytes=4096)
            strict_status, strict_artifacts = run_repository(
                root,
                max_file_size=32,
                max_total_bytes=4096,
                strict=True,
            )

            self.assertEqual("PARTIAL", status)
            self.assertEqual("PARTIAL", artifacts["manifest.json"]["status"])
            self.assertEqual(85, len(artifacts["category-applicability.json"]))
            self.assertTrue(artifacts["mandatory-matchers.json"])
            skipped = artifacts["skipped-files.json"]
            self.assertEqual("dist/system.prompt", skipped[0]["relative_path"])
            self.assertTrue(skipped[0]["generated"])
            self.assertIn("prompt or instruction", skipped[0]["carrier_hints"])
            self.assertIn("security_relevant_file_skipped", {item["condition"] for item in artifacts["coverage-gaps.json"]})
            self.assertEqual("FAILED", strict_status)
            self.assertEqual("FAILED", strict_artifacts["manifest.json"]["status"])
            self.assertEqual(85, len(strict_artifacts["category-applicability.json"]))

            with (
                tempfile.TemporaryDirectory() as output_name,
                tempfile.TemporaryDirectory() as strict_output_name,
                tempfile.TemporaryDirectory() as cache_name,
            ):
                base_command = [
                    sys.executable,
                    str(ROOT / "devin_prepare.py"),
                    "--target-repo",
                    str(root),
                    "--max-file-size",
                    "32",
                    "--max-total-bytes",
                    "4096",
                    "--cache-dir",
                    cache_name,
                    "--no-cache",
                ]
                partial = subprocess.run(
                    [*base_command, "--output-dir", output_name],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                failed = subprocess.run(
                    [*base_command, "--output-dir", strict_output_name, "--strict"],
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(2, partial.returncode)
                self.assertIn("Hunter Accelerator: PARTIAL", partial.stdout)
                self.assertEqual(
                    "PARTIAL",
                    json.loads((Path(output_name) / "manifest.json").read_text(encoding="utf-8"))["status"],
                )
                self.assertEqual(3, failed.returncode)
                self.assertIn("Hunter Accelerator: FAILED", failed.stdout)
                self.assertEqual(
                    "FAILED",
                    json.loads((Path(strict_output_name) / "manifest.json").read_text(encoding="utf-8"))["status"],
                )

    def test_caches_and_installed_dependencies_remain_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "README.md").write_text("plain repository", encoding="utf-8")
            ignored_files = (
                "node_modules/pkg/system.prompt",
                ".venv/lib/secret.py",
                "venv/lib/secret.py",
                "__pycache__/secret.py",
                ".gradle/cache/main.tf",
                "coverage/report/system.prompt",
            )
            for relative in ignored_files:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("openai tool_call api_secret resource", encoding="utf-8")

            status, artifacts = run_repository(root)

            self.assertEqual("COMPLETE", status)
            self.assertEqual(["README.md"], [item["relative_path"] for item in artifacts["file-inventory.jsonl"]])
            self.assertEqual([], artifacts["coverage-gaps.json"])


if __name__ == "__main__":
    unittest.main()
