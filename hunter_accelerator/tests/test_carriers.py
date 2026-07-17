from __future__ import annotations

import unittest

from helpers import FIXTURES, run_repository


class CarrierTests(unittest.TestCase):
    def test_infrastructure_and_hydra_carriers(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "infrastructure")
        carriers = artifacts["carrier-inventory.json"]
        types = {item["carrier_type"] for item in carriers}
        self.assertTrue({"CI/CD", "Hydra buildpack", "Helm", "Kubernetes", "container", "container CI/CD"}.issubset(types))
        hydra = [item for item in carriers if item["carrier_type"] == "Hydra buildpack"]
        self.assertTrue(any(63 in item["classes_activated"] for item in hydra))

    def test_mobile_and_llm_content_carriers(self) -> None:
        _status, mobile = run_repository(FIXTURES / "mobile")
        self.assertIn("mobile", {item["carrier_type"] for item in mobile["carrier-inventory.json"]})
        _status, ai = run_repository(FIXTURES / "llm_agentic")
        prompt = [item for item in ai["carrier-inventory.json"] if item["carrier_type"] == "prompt or instruction"]
        self.assertTrue(prompt)
        self.assertEqual(list(range(66, 86)), prompt[0]["classes_activated"])


if __name__ == "__main__":
    unittest.main()
