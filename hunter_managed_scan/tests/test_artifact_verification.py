from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from hunter_managed_scan.errors import SchemaValidationError, VerificationError
from hunter_managed_scan.adapters._accelerator import CANONICAL_TAXONOMY
from hunter_managed_scan.utilities.json_io import write_json, write_jsonl
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.verify_child_artifacts import verify_child_task
from hunter_managed_scan.utilities.verify_excerpts import verify_finding_excerpts
from hunter_managed_scan.tests.helpers import clone, finding


class ArtifactVerificationTests(unittest.TestCase):
    def child_tree(self, root: Path, *, commit: str = "a" * 40, coverage=None, findings=None, valid_result: bool = True):
        run = root / "results" / "scan_runs" / "run-1"
        child = root / "fetched" / "scan_runs" / "run-1" / "tasks" / "task-1"
        child.mkdir(parents=True)
        (run / "inventory" / "accelerator").mkdir(parents=True)
        write_json(
            run / "run-manifest.json",
            {
                "run_id": "run-1", "target_repository": "example/target", "target_commit": "a" * 40,
                "results_repo_path": str(root / "results"),
                "taxonomy_file": str(CANONICAL_TAXONOMY),
                "initial_target_snapshot": {"commit_sha": "a" * 40, "status_porcelain": "", "diff_sha256": "0" * 64},
            },
        )
        child_manifest = {
            "run_id": "run-1", "task_id": "task-1", "target_repository": "example/target",
            "target_commit": commit, "result_branch": "hunter-run/run-1/task-1"
        }
        result = {
            "schema_version": 1, "run_id": "run-1", "task_id": "task-1",
            "target_repository": "example/target", "target_commit": commit, "status": "COMPLETE",
            "coverage_file": "coverage.json", "findings_file": "findings.json",
            "evidence_file": "evidence.jsonl", "target_unchanged": True,
        }
        if not valid_result:
            del result["coverage_file"]
        write_json(child / "manifest.json", child_manifest)
        write_json(child / "result.json", result)
        write_json(child / "coverage.json", coverage if coverage is not None else [
            {"class_number": 1, "review_status": "REVIEWED_NO_FINDING"},
            {"class_number": 2, "review_status": "REVIEWED_NO_FINDING"},
        ])
        write_json(child / "findings.json", findings or [])
        write_jsonl(child / "evidence.jsonl", [])
        write_jsonl(run / "inventory" / "accelerator" / "file-inventory.jsonl", [])
        package = {
            "task_id": "task-1", "assigned_classes": [1, 2], "result_branch": "hunter-run/run-1/task-1"
        }
        return run, child, package

    def test_excerpt_verification_accepts_exact_excerpt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            excerpt = "dangerous(user_input)"
            (root / "src" / "app.py").write_text(excerpt + "\n", encoding="utf-8")
            verify_finding_excerpts(root, finding(excerpt=excerpt))

    def test_excerpt_verification_rejects_changed_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("safe(user_input)\n", encoding="utf-8")
            with self.assertRaises(VerificationError):
                verify_finding_excerpts(root, finding())

    def test_excerpt_verification_rejects_wrong_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("dangerous(user_input)\n", encoding="utf-8")
            value = finding()
            value["affected_instances"][0]["excerpt_sha256"] = "0" * 64
            with self.assertRaises(VerificationError):
                verify_finding_excerpts(root, value)

    def test_schema_invalid_child_result_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, child, package = self.child_tree(root, valid_result=False)
            with self.assertRaises(SchemaValidationError):
                verify_child_task(
                    run_dir=run, work_package=package, child_artifact_dir=child,
                    target_repo_path=root / "target", changed_paths=["scan_runs/run-1/tasks/task-1/result.json"]
                )

    def test_wrong_target_commit_is_detectable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, child, package = self.child_tree(root, commit="b" * 40)
            with self.assertRaises(VerificationError):
                verify_child_task(
                    run_dir=run, work_package=package, child_artifact_dir=child,
                    target_repo_path=root / "target", changed_paths=["scan_runs/run-1/tasks/task-1/result.json"]
                )

    def test_missing_assigned_class_coverage_is_detectable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run, child, package = self.child_tree(
                root, coverage=[{"class_number": 1, "review_status": "REVIEWED_NO_FINDING"}]
            )
            with self.assertRaises(VerificationError):
                verify_child_task(
                    run_dir=run, work_package=package, child_artifact_dir=child,
                    target_repo_path=root / "target", changed_paths=["scan_runs/run-1/tasks/task-1/result.json"]
                )

    def test_finding_schema_rejects_missing_path(self):
        value = finding()
        del value["attack_path"]
        with self.assertRaises(SchemaValidationError):
            validate_artifact(value, "finding.schema.json")

    def test_child_finding_rejects_wrong_authoritative_owasp_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = finding()
            candidate["owasp"] = "A01"
            run, child, package = self.child_tree(root, findings=[candidate])
            with self.assertRaisesRegex(VerificationError, "authoritative owasp"):
                verify_child_task(
                    run_dir=run, work_package=package, child_artifact_dir=child,
                    target_repo_path=root / "target", changed_paths=["scan_runs/run-1/tasks/task-1/result.json"]
                )

    def test_affected_instance_hash_uses_exact_characters(self):
        value = finding(excerpt="x  y")
        digest = hashlib.sha256("x  y".encode()).hexdigest()
        self.assertEqual(value["affected_instances"][0]["excerpt_sha256"], digest)
        self.assertNotEqual(digest, hashlib.sha256("x y".encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
