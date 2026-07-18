from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from hunter_managed_scan.errors import IncompleteCoverageError, MissingValidationError, SchemaValidationError, VerificationError
from hunter_managed_scan.utilities.apply_critic_results import apply_critic_results
from hunter_managed_scan.utilities.cluster_root_causes import cluster_findings
from hunter_managed_scan.utilities.create_validation_packs import create_validation_packs
from hunter_managed_scan.utilities.cvss import calculate_base_score
from hunter_managed_scan.utilities.verify_validation_artifacts import (
    has_executable_attempt,
    validate_runtime_result,
    verify_command_outputs,
)
from hunter_managed_scan.tests.helpers import VECTOR_MEDIUM, clone, finding, validation


def critic(decisions):
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "target_repository": "example/target",
        "target_commit": "a" * 40,
        "produced_by": "critic",
        "decisions": decisions,
    }


class FindingValidationCriticTests(unittest.TestCase):
    def write_command_outputs(self, root: Path) -> None:
        output = root / "command-output"
        output.mkdir()
        (output / "test-1.stdout").write_text("test-output\n", encoding="utf-8")
        (output / "test-1.stderr").write_text("", encoding="utf-8")
        (output / "control-1.stdout").write_text("control-output\n", encoding="utf-8")
        (output / "control-1.stderr").write_text("", encoding="utf-8")

    def test_exact_duplicates_preserve_affected_instances(self):
        first = finding("HMS-001")
        second = clone(first)
        second["finding_id"] = "HMS-002"
        result = cluster_findings([first, second])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["findings"][0]["affected_instances"]), 1)
        self.assertEqual(result["exact_duplicate_groups"][0]["merged_finding_ids"], ["HMS-002"])

    def test_distinct_business_workflows_are_not_merged(self):
        first = finding("HMS-001", workflow="POST /accounts/{id}")
        second = finding("HMS-002", workflow="POST /transfers/{id}")
        result = cluster_findings([first, second])
        self.assertEqual(len(result["findings"]), 2)

    def test_distinct_security_properties_are_not_merged(self):
        first = finding("HMS-001")
        second = finding("HMS-002")
        second["security_property"] = "authorization integrity"
        self.assertEqual(len(cluster_findings([first, second])["findings"]), 2)

    def test_compatible_findings_group_in_one_pack(self):
        findings = [finding("HMS-001"), finding("HMS-002", file="src/other.py")]
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40, findings=findings
        )
        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0].finding_ids, ("HMS-001", "HMS-002"))

    def test_incompatible_toolchains_are_separated(self):
        findings = [finding("HMS-001", file="src/app.py"), finding("HMS-002", file="src/App.java")]
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40, findings=findings
        )
        self.assertEqual({item.environment_family for item in packs}, {"python", "java"})

    def test_two_maven_modules_are_separate_packs(self):
        findings = [
            finding("JAVA-A", file="services/a/src/main/java/App.java"),
            finding("JAVA-B", file="services/b/src/main/java/App.java"),
        ]
        inventory = ["pom.xml", "services/a/pom.xml", "services/b/pom.xml"]
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40,
            findings=findings, inventory=inventory,
        )
        self.assertEqual(len(packs), 2)
        self.assertEqual({item.compatibility_key["module_root"] for item in packs}, {"services/a", "services/b"})

    def test_two_node_applications_are_separate_packs(self):
        findings = [finding("NODE-A", file="apps/a/src/app.ts"), finding("NODE-B", file="apps/b/src/app.ts")]
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40,
            findings=findings, inventory=["apps/a/package.json", "apps/b/package.json"],
        )
        self.assertEqual(len(packs), 2)

    def test_github_actions_findings_share_ci_pack(self):
        findings = [
            finding("CI-A", file=".github/workflows/build.yml"),
            finding("CI-B", file=".github/workflows/release.yml"),
        ]
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40, findings=findings
        )
        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0].environment_family, "ci-cd")

    def test_helm_and_terraform_are_never_grouped(self):
        helm = finding("HELM", file="charts/api/Chart.yaml")
        helm["category"] = "Helm configuration"
        terraform = finding("TF", file="infra/main.tf")
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40,
            findings=[helm, terraform], inventory=["charts/api/Chart.yaml", "infra/main.tf"],
        )
        self.assertEqual({item.environment_family for item in packs}, {"helm", "terraform"})

    def test_root_cause_cluster_with_multiple_instances_stays_together(self):
        clustered = finding("CLUSTER", file="apps/api/src/a.ts")
        second = clone(clustered["affected_instances"][0])
        second["file"] = "apps/api/src/b.ts"
        second["endpoint_or_workflow"] = "POST /accounts/b"
        clustered["affected_instances"].append(second)
        packs = create_validation_packs(
            run_id="run-1", target_repository="example/target", target_commit="a" * 40,
            findings=[clustered], inventory=["apps/api/package.json"],
        )
        self.assertEqual(len(packs), 1)
        self.assertEqual(packs[0].finding_ids, ("CLUSTER",))

    def test_pack_limit_fails_without_mixing_incompatible_environments(self):
        findings = [
            finding("PY", file="a.py"), finding("JAVA", file="a.java"), finding("NODE", file="a.ts")
        ]
        with self.assertRaises(IncompleteCoverageError):
            create_validation_packs(
                run_id="run-1",
                target_repository="example/target",
                target_commit="a" * 40,
                findings=findings,
                maximum_children=2,
            )

    def test_every_final_finding_requires_validation(self):
        decision = {
            "finding_id": "HMS-001", "verdict": "CONFIRMED", "reason": "supported",
            "corrected_severity": None, "corrected_cvss_vector": None, "contradicting_evidence": []
        }
        with self.assertRaises(MissingValidationError):
            apply_critic_results(
                findings=[finding()], validation_results=[], critic=critic([decision]), run_id="run-1",
                target_repository="example/target", target_commit="a" * 40
            )

    def test_inconclusive_requires_an_executable_attempt(self):
        result = validation(status="INCONCLUSIVE")
        result["commands"] = []
        self.assertFalse(has_executable_attempt(result))

    def test_inconclusive_requires_blocking_details(self):
        result = validation(status="INCONCLUSIVE")
        with self.assertRaises(VerificationError):
            validate_runtime_result(result)
        result["blocking_condition"] = "The external gateway is unavailable in an isolated environment."
        result["missing_evidence"] = ["gateway policy evaluation"]
        result["confirmation_criteria"] = "A local gateway reproduces or rejects the request."
        validate_runtime_result(result)

    def test_fabricated_command_output_hash_is_rejected(self):
        result = validation()
        result["commands"][0]["stdout_sha256"] = "f" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_command_outputs(root)
            with self.assertRaisesRegex(VerificationError, "fabricated or mismatched"):
                verify_command_outputs(result, root)

    def test_command_outputs_with_matching_hashes_are_accepted(self):
        result = validation()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_command_outputs(root)
            verify_command_outputs(result, root)

    def test_missing_control_command_is_rejected(self):
        result = validation()
        result["commands"] = [result["commands"][0]]
        result["reproduction_steps"] = ["Run command:test-1."]
        with self.assertRaisesRegex(VerificationError, "control command"):
            validate_runtime_result(result)

    def test_identical_test_and_control_claim_is_rejected(self):
        result = validation()
        result["commands"][1]["command"] = result["commands"][0]["command"]
        with self.assertRaisesRegex(VerificationError, "identical unsupported claims"):
            validate_runtime_result(result)

    def test_missing_command_exit_code_is_rejected(self):
        result = validation()
        del result["commands"][0]["exit_code"]
        with self.assertRaises(SchemaValidationError):
            validate_runtime_result(result)

    def test_output_not_tied_to_command_is_rejected(self):
        result = validation()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_command_outputs(root)
            (root / "command-output" / "fabricated.stdout").write_text("unowned\n", encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "not tied"):
                verify_command_outputs(result, root)

    def test_reproduction_unknown_command_id_is_rejected(self):
        result = validation()
        result["reproduction_steps"][0] = "Run command:unknown-test."
        with self.assertRaisesRegex(VerificationError, "unknown command ID"):
            validate_runtime_result(result)

    def test_critic_rejection_removes_finding(self):
        decision = {
            "finding_id": "HMS-001", "verdict": "REJECTED", "reason": "control disproved the path",
            "corrected_severity": None, "corrected_cvss_vector": None,
            "contradicting_evidence": ["validation control"]
        }
        result = apply_critic_results(
            findings=[finding()], validation_results=[validation()], critic=critic([decision]), run_id="run-1",
            target_repository="example/target", target_commit="a" * 40
        )
        self.assertEqual(result, [])

    def test_false_positive_validation_must_be_rejected(self):
        decision = {
            "finding_id": "HMS-001", "verdict": "CONFIRMED", "reason": "unsupported",
            "corrected_severity": None, "corrected_cvss_vector": None, "contradicting_evidence": []
        }
        with self.assertRaises(VerificationError):
            apply_critic_results(
                findings=[finding()], validation_results=[validation(status="FALSE_POSITIVE")],
                critic=critic([decision]), run_id="run-1", target_repository="example/target", target_commit="a" * 40
            )

    def test_critic_downgrade_updates_severity_and_cvss(self):
        decision = {
            "finding_id": "HMS-001", "verdict": "DOWNGRADED", "reason": "runtime precondition narrows impact",
            "corrected_severity": "MEDIUM", "corrected_cvss_vector": VECTOR_MEDIUM,
            "contradicting_evidence": ["local validation"]
        }
        result = apply_critic_results(
            findings=[finding()], validation_results=[validation()], critic=critic([decision]), run_id="run-1",
            target_repository="example/target", target_commit="a" * 40
        )
        self.assertEqual(result[0]["severity"], "MEDIUM")
        self.assertEqual(result[0]["cvss_score"], calculate_base_score(VECTOR_MEDIUM))

    def test_critic_must_decide_every_finding_once(self):
        with self.assertRaises(VerificationError):
            apply_critic_results(
                findings=[finding()], validation_results=[validation()], critic=critic([]), run_id="run-1",
                target_repository="example/target", target_commit="a" * 40
            )


if __name__ == "__main__":
    unittest.main()
