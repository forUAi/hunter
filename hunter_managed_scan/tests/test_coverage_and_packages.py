from __future__ import annotations

import subprocess
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

from hunter_managed_scan.adapters import _accelerator  # noqa: F401
from hunter_accelerator.taxonomy import load_and_validate_taxonomy

from hunter_managed_scan.adapters.carrier_adapter import class_specific_evidence
from hunter_managed_scan.adapters._accelerator import CANONICAL_TAXONOMY
from hunter_managed_scan.models.manifest import BudgetConfiguration
from hunter_managed_scan.utilities.create_coverage_plan import create_coverage_plan
from hunter_managed_scan.utilities.create_work_packages import create_work_packages
from hunter_managed_scan.utilities.prepare_run import prepare_run
from hunter_managed_scan.utilities.target_guard import capture_target_snapshot
from hunter_managed_scan.tests.helpers import preparation


class CoverageAndPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.taxonomy = load_and_validate_taxonomy(CANONICAL_TAXONOMY)

    def plan(self, prepared=None):
        return create_coverage_plan(
            run_id="run-1",
            target_repository="example/target",
            target_commit="a" * 40,
            taxonomy=self.taxonomy,
            preparation=prepared or preparation(),
        )

    def test_existing_accelerator_command_still_loads(self):
        root = Path(__file__).resolve().parents[2]
        completed = subprocess.run(
            [sys.executable, str(root / "hunter_accelerator" / "devin_prepare.py"), "--help"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Hunter", completed.stdout)

    def test_all_85_classes_appear_in_plan(self):
        plan = self.plan()
        self.assertEqual([entry.class_number for entry in plan.entries], list(range(1, 86)))

    def test_generic_source_does_not_activate_unrelated_class(self):
        item = {"carrier_type": "source code", "file": "src/app.py", "classes_activated": [13]}
        self.assertEqual(class_specific_evidence(13, [item], {"positive_matches": []}), [])

    def test_lockfile_only_mobile_string_does_not_activate_mobile(self):
        item = {"carrier_type": "mobile", "file": "package-lock.json", "classes_activated": [64]}
        self.assertEqual(class_specific_evidence(64, [item], {"positive_matches": []}), [])

    def test_outbound_http_activates_ssrf_review(self):
        carrier = {"carrier_type": "outbound HTTP", "file": "src/client.py", "classes_activated": [13]}
        plan = self.plan(preparation([carrier]))
        entry = plan.entries[12]
        self.assertEqual(entry.preliminary_state, "ASSIGNED_TO_INVESTIGATION")
        self.assertEqual(entry.candidate_files, ("src/client.py",))

    def test_prompt_model_tool_activates_llm_review(self):
        carrier = {"carrier_type": "prompt or instruction", "file": "agent.py", "classes_activated": [66, 71]}
        plan = self.plan(preparation([carrier]))
        self.assertEqual(plan.entries[65].preliminary_state, "ASSIGNED_TO_INVESTIGATION")
        self.assertEqual(plan.entries[70].preliminary_state, "ASSIGNED_TO_INVESTIGATION")

    def test_every_class_has_owner_and_review_state(self):
        plan = self.plan()
        self.assertTrue(all(entry.task_ids and entry.preliminary_state for entry in plan.entries))
        self.assertTrue(all("coverage-auditor" in entry.task_ids for entry in plan.entries))

    def test_work_packages_are_deterministic(self):
        plan = self.plan()
        first = [item.as_dict() for item in create_work_packages(plan=plan, preparation=preparation(), budgets=BudgetConfiguration())]
        second = [item.as_dict() for item in create_work_packages(plan=plan, preparation=preparation(), budgets=BudgetConfiguration())]
        self.assertEqual(first, second)
        self.assertEqual([item["task_id"] for item in first], sorted(item["task_id"] for item in first))

    def test_work_packages_are_not_one_per_matcher(self):
        prepared = preparation()
        prepared["matchers"] = [
            {"class_number": 1, "matcher_family": "raw-query", "matcher_id": f"m-{index}"}
            for index in range(50)
        ]
        packages = create_work_packages(plan=self.plan(prepared), preparation=prepared, budgets=BudgetConfiguration())
        self.assertLessEqual(len(packages), 7)
        self.assertLess(len(packages), len(prepared["matchers"]))

    def test_coverage_auditor_receives_all_classes(self):
        packages = create_work_packages(plan=self.plan(), preparation=preparation(), budgets=BudgetConfiguration())
        auditor = next(item for item in packages if item.task_id == "coverage-auditor")
        self.assertEqual(auditor.assigned_classes, tuple(range(1, 86)))

    def test_fixture_families_exist(self):
        fixtures = Path(__file__).parent / "fixtures"
        for name in ("frontend", "java-backend", "cicd-only", "container-iac", "llm-agentic"):
            self.assertTrue((fixtures / name).is_dir())

    def test_prepare_end_to_end_records_repository_commit_and_preserves_target(self):
        fixture = Path(__file__).parent / "fixtures" / "llm-agentic"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            results = root / "results"
            shutil.copytree(fixture, target)
            results.mkdir()
            for repository, branch in ((target, "main"), (results, "hunter-managed-test")):
                subprocess.run(["git", "init", "-b", branch], cwd=repository, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=repository, check=True)
                subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repository, check=True)
                marker = repository / ".results-marker" if repository == results else None
                if marker:
                    marker.write_text("managed results fixture\n", encoding="utf-8")
                subprocess.run(["git", "add", "."], cwd=repository, check=True)
                subprocess.run(["git", "commit", "-m", "fixture"], cwd=repository, stdout=subprocess.DEVNULL, check=True)
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=target, text=True, stdout=subprocess.PIPE, check=True
            ).stdout.strip()
            before = capture_target_snapshot(target, results)
            run_dir, output = prepare_run(
                target_repo_path=target,
                target_repository="example/llm-agentic",
                target_commit=commit,
                results_repo_path=results,
                results_branch="hunter-managed-test",
                run_id="hunter-fixture",
                created_at="2026-07-18T00:00:00Z",
            )
            after = capture_target_snapshot(target, results)
            self.assertEqual(before, after)
            self.assertEqual(output["manifest"]["target_repository"], "example/llm-agentic")
            self.assertEqual(output["manifest"]["target_commit"], commit)
            self.assertEqual(len(output["coverage_plan"]["entries"]), 85)
            self.assertLessEqual(len(output["work_packages"]), 7)
            self.assertFalse((run_dir / "findings-final.json").exists())


if __name__ == "__main__":
    unittest.main()
