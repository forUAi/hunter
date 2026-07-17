from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import run_repository, tree_digest


class GitMetadataTests(unittest.TestCase):
    def test_unresolved_gitfile_is_partial_and_class_24_is_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".git").write_text("gitdir: ../missing-git-metadata\n", encoding="utf-8")
            (root / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")

            status, artifacts = run_repository(root)

            self.assertEqual("PARTIAL", status)
            class_24 = artifacts["category-applicability.json"][23]
            self.assertEqual(24, class_24["class_number"])
            self.assertEqual("UNRESOLVED", class_24["status"])
            self.assertEqual("unresolved", class_24["git_metadata_status"])
            self.assertIn("git_metadata_unresolved", {item["condition"] for item in artifacts["coverage-gaps.json"]})
            profile = artifacts["repository-profile.json"]
            self.assertEqual("unresolved", profile["git_metadata_status"])
            self.assertFalse(profile["has_git_history"])
            manifest = artifacts["manifest.json"]
            self.assertEqual(str(root.resolve()), manifest["target_repository"])
            self.assertIsNone(manifest["commit_sha"])
            self.assertEqual("unresolved", manifest["git_metadata_status"])

    @unittest.skipUnless(shutil.which("git"), "Git is required for gitfile coverage")
    def test_synthetic_submodule_style_gitfile_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            root = base / "target"
            metadata = base / "git-metadata"
            root.mkdir()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=Hunter Tests",
                    "-c",
                    "user.email=hunter-tests@example.invalid",
                    "commit",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            expected_commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            (root / ".git").rename(metadata)
            (root / ".git").write_text(f"gitdir: {metadata}\n", encoding="utf-8")

            status, artifacts = run_repository(root)

            self.assertEqual("COMPLETE", status)
            self.assertEqual(expected_commit, artifacts["manifest.json"]["commit_sha"])
            self.assertEqual("resolved", artifacts["manifest.json"]["git_metadata_status"])
            self.assertEqual("APPLICABLE", artifacts["category-applicability.json"][23]["status"])

    @unittest.skipUnless(shutil.which("git"), "Git is required for worktree coverage")
    def test_real_git_worktree_populates_commit_status_and_class_24(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            main = base / "main"
            worktree = base / "worktree"
            main.mkdir()
            subprocess.run(["git", "init", "-q", str(main)], check=True)
            (main / "app.py").write_text("def main():\n    pass\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(main), "add", "app.py"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(main),
                    "-c",
                    "user.name=Hunter Tests",
                    "-c",
                    "user.email=hunter-tests@example.invalid",
                    "commit",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(main), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", str(main), "worktree", "add", "--detach", str(worktree)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertTrue((worktree / ".git").is_file())
            before = tree_digest(worktree)

            status, artifacts = run_repository(worktree)

            self.assertEqual("COMPLETE", status)
            profile = artifacts["repository-profile.json"]
            self.assertEqual(commit, profile["commit_sha"])
            self.assertEqual("clean", profile["working_tree_status"])
            self.assertTrue(profile["has_git_history"])
            self.assertEqual("resolved", profile["git_metadata_status"])
            class_24 = artifacts["category-applicability.json"][23]
            self.assertEqual("APPLICABLE", class_24["status"])
            self.assertTrue(any(item["carrier_type"] == "git history" for item in artifacts["carrier-inventory.json"]))
            manifest = artifacts["manifest.json"]
            self.assertEqual(str(worktree.resolve()), manifest["target_repository"])
            self.assertEqual(commit, manifest["commit_sha"])
            self.assertEqual("clean", manifest["working_tree_state"])
            self.assertEqual("resolved", manifest["git_metadata_status"])
            self.assertNotIn(".git", {item["relative_path"] for item in artifacts["file-inventory.jsonl"]})
            self.assertEqual(before, tree_digest(worktree))


if __name__ == "__main__":
    unittest.main()
