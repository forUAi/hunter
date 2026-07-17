from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import TAXONOMY, tree_digest
from hunter_accelerator.file_inventory import FileInventoryBuilder
from hunter_accelerator.workspace import RepositoryWorkspace
from hunter_accelerator.errors import WorkspaceSafetyError


class WorkspaceTests(unittest.TestCase):
    def test_rejects_nonexistent_repository_and_internal_output(self) -> None:
        with self.assertRaises(WorkspaceSafetyError):
            RepositoryWorkspace(Path("/definitely/missing/hunter-repo"), Path("/tmp/out"), Path("/tmp/cache"))
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with self.assertRaises(WorkspaceSafetyError):
                RepositoryWorkspace(root, root / "output", Path("/tmp/cache"))

    def test_symlink_escape_is_rejected_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as repo_name, tempfile.TemporaryDirectory() as outside_name, tempfile.TemporaryDirectory() as output_name:
            root = Path(repo_name)
            outside = Path(outside_name) / "outside.py"
            outside.write_text("print('outside')", encoding="utf-8")
            (root / "escape.py").symlink_to(outside)
            workspace = RepositoryWorkspace(root, Path(output_name), Path(output_name) / "cache")
            inventory = FileInventoryBuilder(workspace, 1024, 4096)
            records, skipped = inventory.scan(lambda _record, _text: None)
            self.assertEqual([], records)
            self.assertEqual("symlink file escapes target repository", skipped[0].reason)
            self.assertIn("source code", skipped[0].carrier_hints)

    def test_binary_and_skipped_files_are_recorded_without_target_writes(self) -> None:
        with tempfile.TemporaryDirectory() as repo_name, tempfile.TemporaryDirectory() as output_name:
            root = Path(repo_name)
            (root / "binary.apk").write_bytes(b"PK\x00binary")
            (root / "large.py").write_text("x" * 200, encoding="utf-8")
            before = tree_digest(root)
            workspace = RepositoryWorkspace(root, Path(output_name), Path(output_name) / "cache")
            inventory = FileInventoryBuilder(workspace, 32, 1024)
            records, skipped = inventory.scan(lambda _record, _text: None)
            self.assertTrue(records[0].binary)
            self.assertEqual("file exceeds max-file-size", skipped[0].reason)
            self.assertEqual(before, tree_digest(root))


if __name__ == "__main__":
    unittest.main()
