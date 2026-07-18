from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from hunter_managed_scan import (
    INCOMPLETE_COVERAGE,
    MISSING_VALIDATION,
    OPERATIONAL_ERROR,
    SCHEMA_OR_VERIFICATION_FAILURE,
    SUCCESS,
    TARGET_REPOSITORY_MODIFIED,
)
from hunter_managed_scan.errors import IncompleteCoverageError, MissingValidationError, TargetModifiedError
from hunter_managed_scan.orchestration.session_gateway import SessionGateway, SessionStatus
from hunter_managed_scan.utilities.audit_log import AuditLog, aggregate_acu_usage
from hunter_managed_scan.utilities.completion_gate import completion_gate
from hunter_managed_scan.utilities.coverage_audit import apply_coverage_audit, audit_from_verified_receipt
from hunter_managed_scan.utilities.json_io import read_jsonl, write_json, write_jsonl
from hunter_managed_scan.utilities.schema_validation import validate_artifact
from hunter_managed_scan.utilities.target_guard import capture_target_snapshot
from hunter_managed_scan.tests.helpers import finding


def plan_entries(count: int = 85):
    return [
        {
            "class_number": number,
            "class_name": f"Class {number}",
            "preliminary_state": "NEGATIVE_EVIDENCE_REVIEW",
            "task_ids": ["task", "coverage-auditor"],
            "candidate_files": [],
            "carrier_evidence": [],
            "negative_evidence": [{}],
            "logic_targets": [],
            "requires_manual_review": True,
        }
        for number in range(1, count + 1)
    ]


def coverage_entries(count: int = 85):
    return [
        {
            "class_number": number,
            "final_state": "NEGATIVE_EVIDENCE_ACCEPTED",
            "reviewed_by": "coverage-auditor",
            "notes": "Independent review completed.",
            "coverage_gap": False,
        }
        for number in range(1, count + 1)
    ]


def build_empty_complete_run(root: Path):
    target = root / "target"
    results = root / "results"
    target.mkdir()
    results.mkdir()
    (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    for command in (["git", "init"], ["git", "config", "user.email", "fixture@example.invalid"], ["git", "config", "user.name", "Fixture"], ["git", "add", "."], ["git", "commit", "-m", "fixture"]):
        subprocess.run(command, cwd=target, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    snapshot = capture_target_snapshot(target, results)
    run = results / "scan_runs" / "run"
    for path in ("coverage", "work-packages", "investigation/verified", "investigation/normalized", "root-causes", "validations", "critic"):
        (run / path).mkdir(parents=True, exist_ok=True)
    write_json(run / "run-manifest.json", {
        "run_id": "run", "target_repository": "example/target", "target_commit": snapshot.commit_sha,
        "results_repo_path": str(results), "initial_target_snapshot": snapshot.as_dict(),
        "budgets": {"maximum_total_acu": 55}
    })
    write_json(run / "coverage" / "coverage-plan.json", {"entries": plan_entries()})
    write_json(run / "coverage" / "coverage-final.json", {
        "entries": coverage_entries(), "summary": {"complete": True, "class_count": 85, "coverage_gap_count": 0}
    })
    write_json(run / "work-packages" / "task.json", {"task_id": "task", "logic_targets": [], "security_surfaces": []})
    write_json(run / "work-packages" / "coverage-auditor.json", {"task_id": "coverage-auditor", "logic_targets": [], "security_surfaces": []})
    write_json(run / "investigation" / "verified" / "task.json", {"verification_status": "ACCEPTED"})
    write_json(run / "investigation" / "verified" / "coverage-auditor.json", {"verification_status": "ACCEPTED"})
    write_json(run / "investigation" / "normalized" / "findings.json", [])
    write_json(run / "root-causes" / "findings-clustered.json", [])
    write_json(run / "critic" / "critic-result.json", {
        "schema_version": 1, "run_id": "run", "target_repository": "example/target",
        "target_commit": snapshot.commit_sha, "produced_by": "critic", "decisions": []
    })
    write_json(run / "critic" / "findings-reviewed.json", [])
    write_jsonl(run / "audit-log.jsonl", [])
    return target, run


class CompletionAuditCliTests(unittest.TestCase):
    def test_exit_code_contract(self):
        self.assertEqual(
            (SUCCESS, OPERATIONAL_ERROR, SCHEMA_OR_VERIFICATION_FAILURE, INCOMPLETE_COVERAGE, MISSING_VALIDATION, TARGET_REPOSITORY_MODIFIED),
            (0, 1, 2, 3, 4, 5),
        )

    def test_coverage_audit_accepts_all_85(self):
        plan = {
            "schema_version": 1, "run_id": "run", "target_repository": "example/target",
            "target_commit": "a" * 40, "taxonomy_version": "v1", "entries": plan_entries()
        }
        audit = {
            "schema_version": 1, "run_id": "run", "target_repository": "example/target",
            "target_commit": "a" * 40, "produced_by": "coverage-auditor", "entries": coverage_entries()
        }
        result = apply_coverage_audit(plan, audit)
        self.assertTrue(result["summary"]["complete"])
        self.assertEqual(result["summary"]["class_count"], 85)

    def test_coverage_audit_rejects_missing_class(self):
        plan = {
            "schema_version": 1, "run_id": "run", "target_repository": "example/target",
            "target_commit": "a" * 40, "taxonomy_version": "v1", "entries": plan_entries()
        }
        audit = {
            "schema_version": 1, "run_id": "run", "target_repository": "example/target",
            "target_commit": "a" * 40, "produced_by": "coverage-auditor", "entries": coverage_entries(84)
        }
        with self.assertRaises(Exception):
            apply_coverage_audit(plan, audit)

    def test_accepted_auditor_receipt_converts_without_changing_child_outcomes(self):
        entries = plan_entries()
        entries[0]["preliminary_state"] = "ALWAYS_CHECK"
        plan = {
            "run_id": "run", "target_repository": "example/target", "target_commit": "a" * 40,
            "entries": entries,
        }
        receipt = {
            "task_id": "coverage-auditor", "verification_status": "ACCEPTED",
            "coverage": [
                {"class_number": number, "review_status": "REVIEWED_NO_FINDING", "notes": "Reviewed independently."}
                for number in range(1, 86)
            ],
        }
        audit = audit_from_verified_receipt(plan, receipt)
        self.assertEqual(audit["entries"][0]["final_state"], "REVIEWED")
        self.assertEqual(audit["entries"][1]["final_state"], "NEGATIVE_EVIDENCE_ACCEPTED")
        receipt["coverage"][1]["review_status"] = "CANDIDATE_PRODUCED"
        audit = audit_from_verified_receipt(plan, receipt)
        self.assertEqual(audit["entries"][1]["final_state"], "REVIEWED")
        receipt["coverage"][1]["review_status"] = "COVERAGE_GAP"
        audit = audit_from_verified_receipt(plan, receipt)
        self.assertTrue(audit["entries"][1]["coverage_gap"])

    def test_completion_fails_when_any_class_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "coverage").mkdir()
            write_json(run / "run-manifest.json", {})
            write_json(run / "coverage" / "coverage-plan.json", {"entries": plan_entries(84)})
            write_json(run / "coverage" / "coverage-final.json", {"entries": coverage_entries(84), "summary": {"complete": True}})
            with self.assertRaises(IncompleteCoverageError):
                completion_gate(run_dir=run, target_repo_path=run)

    def test_completion_fails_when_validation_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            for path in ("coverage", "work-packages", "investigation/verified", "investigation/normalized", "root-causes", "validations"):
                (run / path).mkdir(parents=True, exist_ok=True)
            write_json(run / "run-manifest.json", {})
            write_json(run / "coverage" / "coverage-plan.json", {"entries": plan_entries()})
            write_json(run / "coverage" / "coverage-final.json", {"entries": coverage_entries(), "summary": {"complete": True}})
            write_json(run / "work-packages" / "task.json", {"task_id": "task", "logic_targets": [], "security_surfaces": []})
            write_json(run / "work-packages" / "coverage-auditor.json", {"task_id": "coverage-auditor", "logic_targets": [], "security_surfaces": []})
            write_json(run / "investigation" / "verified" / "task.json", {"verification_status": "ACCEPTED"})
            write_json(run / "investigation" / "verified" / "coverage-auditor.json", {"verification_status": "ACCEPTED"})
            candidate = finding()
            write_json(run / "investigation" / "normalized" / "findings.json", [candidate])
            write_json(run / "root-causes" / "findings-clustered.json", [candidate])
            with self.assertRaises(MissingValidationError):
                completion_gate(run_dir=run, target_repo_path=run)

    def test_completion_fails_if_target_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            results = root / "results"
            target.mkdir()
            results.mkdir()
            (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
            for command in (["git", "init"], ["git", "config", "user.email", "fixture@example.invalid"], ["git", "config", "user.name", "Fixture"], ["git", "add", "."], ["git", "commit", "-m", "fixture"]):
                subprocess.run(command, cwd=target, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            snapshot = capture_target_snapshot(target, results)
            run = results / "scan_runs" / "run"
            for path in ("coverage", "work-packages", "investigation/verified", "investigation/normalized", "root-causes", "validations", "critic"):
                (run / path).mkdir(parents=True, exist_ok=True)
            manifest = {
                "run_id": "run", "target_repository": "example/target", "target_commit": snapshot.commit_sha,
                "results_repo_path": str(results), "initial_target_snapshot": snapshot.as_dict()
            }
            write_json(run / "run-manifest.json", manifest)
            write_json(run / "coverage" / "coverage-plan.json", {"entries": plan_entries()})
            write_json(run / "coverage" / "coverage-final.json", {"entries": coverage_entries(), "summary": {"complete": True, "class_count": 85, "coverage_gap_count": 0}})
            write_json(run / "work-packages" / "task.json", {"task_id": "task", "logic_targets": [], "security_surfaces": []})
            write_json(run / "work-packages" / "coverage-auditor.json", {"task_id": "coverage-auditor", "logic_targets": [], "security_surfaces": []})
            write_json(run / "investigation" / "verified" / "task.json", {"verification_status": "ACCEPTED"})
            write_json(run / "investigation" / "verified" / "coverage-auditor.json", {"verification_status": "ACCEPTED"})
            write_json(run / "investigation" / "normalized" / "findings.json", [])
            write_json(run / "root-causes" / "findings-clustered.json", [])
            write_json(run / "critic" / "critic-result.json", {
                "schema_version": 1, "run_id": "run", "target_repository": "example/target",
                "target_commit": snapshot.commit_sha, "produced_by": "critic", "decisions": []
            })
            write_json(run / "critic" / "findings-reviewed.json", [])
            write_jsonl(run / "audit-log.jsonl", [])
            (target / "app.py").write_text("print('changed')\n", encoding="utf-8")
            with self.assertRaises(TargetModifiedError):
                completion_gate(run_dir=run, target_repo_path=target)

    def test_completion_success_writes_all_final_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            target, run = build_empty_complete_run(Path(directory))
            result = completion_gate(run_dir=run, target_repo_path=target)
            self.assertEqual(result["status"], "COMPLETE")
            for name in ("findings-final.json", "final-output.json", "EXECUTIVE_BRIEF.md", "RUN_SUMMARY.md"):
                self.assertTrue((run / name).is_file())

    def test_completion_fails_after_global_budget_exhaustion(self):
        with tempfile.TemporaryDirectory() as directory:
            target, run = build_empty_complete_run(Path(directory))
            AuditLog(run / "audit-log.jsonl").append(
                "GLOBAL_ACU_BUDGET_EXHAUSTED", run_id="run",
                details={"incomplete_task": "critic"}, timestamp="2026-07-18T00:00:00Z",
            )
            with self.assertRaises(IncompleteCoverageError):
                completion_gate(run_dir=run, target_repo_path=target)

    def test_no_target_pr_or_branch_api_exists(self):
        self.assertFalse(hasattr(SessionGateway, "create_branch"))
        self.assertFalse(hasattr(SessionGateway, "open_pull_request"))

    def test_session_boundary_is_mockable(self):
        class FakeGateway:
            def create(self, **_kwargs): return "session-1"
            def status(self, session_id): return SessionStatus(session_id, "settled", 1.25, "hunter-run/run/task")
            def usage(self, _session_id): return 1.25
        gateway = FakeGateway()
        self.assertEqual(gateway.status(gateway.create()).actual_acu, 1.25)

    def test_master_playbook_begins_with_strict_role_gate(self):
        playbook = Path(__file__).resolve().parents[1] / "playbook" / "hunter-managed-security-scan.devin.md"
        lines = playbook.read_text(encoding="utf-8").splitlines()
        self.assertIn("STRICT ROLE-SELECTION GATE", lines[0])
        text = "\n".join(lines[:12])
        for role in ("ORCHESTRATOR", "INVESTIGATOR", "VALIDATOR", "CRITIC"):
            self.assertIn(role, text)

    def test_master_playbook_contains_direct_managed_session_and_git_mechanics(self):
        playbook = Path(__file__).resolve().parents[1] / "playbook" / "hunter-managed-security-scan.devin.md"
        text = playbook.read_text(encoding="utf-8")
        for required in (
            "create_session", "gather_sessions", "get_session_status", "get_session_usage",
            "forUAi/hunter", "authorize-child", "GLOBAL_ACU_BUDGET_EXHAUSTED",
            "git -C \"$RESULTS_REPO_PATH\" worktree add", "git -C \"$RESULTS_REPO_PATH\" restore",
            "required Devin managed-session tools are unavailable",
        ):
            self.assertIn(required, text)

    def test_audit_log_is_deterministic_valid_json_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = AuditLog(path)
            log.append("run_created", run_id="run", timestamp="2026-01-01T00:00:00Z", details={"branch": "test"})
            log.append("session_usage", run_id="run", timestamp="2026-01-01T00:00:01Z", details={"session_id": "s1", "role": "VALIDATOR", "actual_acu": 1.5})
            records = read_jsonl(path)
            self.assertEqual([item["sequence"] for item in records], [1, 2])
            self.assertEqual(aggregate_acu_usage(records)["total_acu"], 1.5)
            for line in path.read_text(encoding="utf-8").splitlines():
                self.assertIsInstance(json.loads(line), dict)

    def test_example_artifacts_validate(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        for filename, schema in (
            ("work-package.json", "work-package.schema.json"),
            ("validation-pack.json", "validation-pack.schema.json"),
            ("child-result.json", "investigation-result.schema.json"),
            ("final-output.json", "final-output.schema.json"),
        ):
            validate_artifact(json.loads((examples / filename).read_text(encoding="utf-8")), schema)


if __name__ == "__main__":
    unittest.main()
