from __future__ import annotations

import unittest

from helpers import FIXTURES, run_repository


class LogicTargetTests(unittest.TestCase):
    def test_spring_fixture_enumerates_business_logic_targets(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "java_spring")
        targets = artifacts["logic-targets.json"]
        capture = next(item for item in targets if item["symbol"] == "capturePayment")
        signals = set(capture["signals"])
        self.assertIn("state-changing endpoint", signals)
        self.assertIn("money, amount, balance, payment or transfer operation", signals)
        self.assertIn("resource lookup by client-provided ID", signals)
        self.assertIn("audit or ledger write", signals)
        self.assertIn("transaction boundary", signals)
        self.assertEqual([10, 11, 12, 14, 49, 50, 55, 56, 57], capture["activated_classes"])

    def test_vertx_fixture_enumerates_identity_and_exception_sensitive_targets(self) -> None:
        _status, artifacts = run_repository(FIXTURES / "java_vertx")
        targets = artifacts["logic-targets.json"]
        self.assertTrue(any("resource lookup by client-provided ID" in item["signals"] for item in targets))
        self.assertTrue(any("multi-step workflow or state machine" in item["signals"] for item in targets))
        self.assertTrue(any("audit or ledger write" in item["signals"] for item in targets))


if __name__ == "__main__":
    unittest.main()
