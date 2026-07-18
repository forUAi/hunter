from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunter_managed_scan.errors import IncompleteCoverageError
from hunter_managed_scan.utilities.acu_budget import acu_budget_snapshot, authorize_child_launch, maximum_possible_acu
from hunter_managed_scan.models.manifest import BudgetConfiguration
from hunter_managed_scan.utilities.audit_log import AuditLog
from hunter_managed_scan.utilities.json_io import read_jsonl


class GlobalAcuBudgetTests(unittest.TestCase):
    def test_default_maximum_possible_calculation_is_globally_capped(self):
        result = maximum_possible_acu(BudgetConfiguration().as_dict())
        self.assertEqual(result["uncapped_maximum_acu"], 235)
        self.assertEqual(result["global_cap_acu"], 55)
        self.assertEqual(result["effective_maximum_acu"], 55)

    def test_initial_launch_reserves_proposed_maximum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            result = authorize_child_launch(
                audit_path=path, run_id="run", maximum_total_acu=55, task_id="investigator-authz",
                role="INVESTIGATOR", phase="INVESTIGATION", proposed_maximum_acu=5,
                timestamp="2026-07-18T00:00:00Z",
            )
            self.assertEqual(result["planned_maximum_acu"], 5)
            self.assertEqual(result["outstanding_reserved_acu"], 5)
            self.assertEqual(result["available_for_new_launch_acu"], 50)
            self.assertEqual(result["planned_maximum_acu_by_phase"], {"INVESTIGATION": 5.0})
            self.assertEqual(result["planned_maximum_acu_by_role"], {"INVESTIGATOR": 5.0})

    def test_cumulative_parent_usage_updates_do_not_double_count(self):
        records = [
            {"event": "session_usage", "details": {"session_id": "parent", "role": "ORCHESTRATOR", "phase": "PARENT", "actual_acu": 2}},
            {"event": "session_usage", "details": {"session_id": "parent", "role": "ORCHESTRATOR", "phase": "PARENT", "actual_acu": 3}},
        ]
        snapshot = acu_budget_snapshot(records, 55)
        self.assertEqual(snapshot["actual_acu"], 3)

    def test_retry_uses_actual_prior_acu_and_tracks_retry_acu(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            authorize_child_launch(
                audit_path=path, run_id="run", maximum_total_acu=55, task_id="validator-java",
                role="VALIDATOR", phase="VALIDATION", proposed_maximum_acu=7, retry_number=0,
                timestamp="2026-07-18T00:00:00Z",
            )
            log = AuditLog(path)
            log.append(
                "session_usage", run_id="run", timestamp="2026-07-18T00:01:00Z",
                details={"task_id": "validator-java", "retry_number": 0, "role": "VALIDATOR", "phase": "VALIDATION", "actual_acu": 3},
            )
            authorize_child_launch(
                audit_path=path, run_id="run", maximum_total_acu=55, task_id="validator-java",
                role="VALIDATOR", phase="VALIDATION", proposed_maximum_acu=7, retry_number=1,
                verification_error="excerpt hash mismatch at src/App.java:10",
                timestamp="2026-07-18T00:02:00Z",
            )
            log.append(
                "session_usage", run_id="run", timestamp="2026-07-18T00:03:00Z",
                details={"task_id": "validator-java", "retry_number": 1, "role": "VALIDATOR", "phase": "VALIDATION", "actual_acu": 2},
            )
            snapshot = acu_budget_snapshot(read_jsonl(path), 55)
            self.assertEqual(snapshot["actual_acu"], 5)
            self.assertEqual(snapshot["retry_acu"], 2)
            self.assertEqual(snapshot["actual_acu_by_phase"], {"VALIDATION": 5.0})
            self.assertEqual(snapshot["actual_acu_by_role"], {"VALIDATOR": 5.0})
            retry_launch = [item for item in read_jsonl(path) if item["event"] == "child_launch_authorized"][-1]
            self.assertEqual(
                retry_launch["details"]["verification_error"],
                "excerpt hash mismatch at src/App.java:10",
            )

    def test_exact_global_budget_boundary_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            AuditLog(path).append(
                "session_usage", run_id="run", timestamp="2026-07-18T00:00:00Z",
                details={"task_id": "parent", "retry_number": 0, "role": "ORCHESTRATOR", "phase": "PREPARATION", "actual_acu": 50},
            )
            result = authorize_child_launch(
                audit_path=path, run_id="run", maximum_total_acu=55, task_id="critic",
                role="CRITIC", phase="CRITIC", proposed_maximum_acu=5,
                timestamp="2026-07-18T00:01:00Z",
            )
            self.assertEqual(result["available_for_new_launch_acu"], 0)

    def test_exhaustion_records_event_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            AuditLog(path).append(
                "session_usage", run_id="run", timestamp="2026-07-18T00:00:00Z",
                details={"task_id": "spent", "retry_number": 0, "role": "INVESTIGATOR", "phase": "INVESTIGATION", "actual_acu": 51},
            )
            with self.assertRaisesRegex(IncompleteCoverageError, "GLOBAL_ACU_BUDGET_EXHAUSTED"):
                authorize_child_launch(
                    audit_path=path, run_id="run", maximum_total_acu=55, task_id="validator-node",
                    role="VALIDATOR", phase="VALIDATION", proposed_maximum_acu=5,
                    timestamp="2026-07-18T00:01:00Z",
                )
            event = read_jsonl(path)[-1]
            self.assertEqual(event["event"], "GLOBAL_ACU_BUDGET_EXHAUSTED")
            self.assertEqual(event["details"]["incomplete_task"], "validator-node")

    def test_parallel_outstanding_reservations_cannot_overcommit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            authorize_child_launch(
                audit_path=path, run_id="run", maximum_total_acu=55, task_id="wave-a",
                role="INVESTIGATOR", phase="INVESTIGATION", proposed_maximum_acu=50,
                timestamp="2026-07-18T00:00:00Z",
            )
            with self.assertRaises(IncompleteCoverageError):
                authorize_child_launch(
                    audit_path=path, run_id="run", maximum_total_acu=55, task_id="wave-b",
                    role="INVESTIGATOR", phase="INVESTIGATION", proposed_maximum_acu=6,
                    timestamp="2026-07-18T00:01:00Z",
                )


if __name__ == "__main__":
    unittest.main()
