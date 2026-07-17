from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import TAXONOMY
from hunter_accelerator.taxonomy import (
    EXPECTED_ABSENCE,
    EXPECTED_ALWAYS,
    EXPECTED_BUILDERS,
    EXPECTED_LOGIC,
    load_and_validate_taxonomy,
)
from hunter_accelerator.errors import TaxonomyValidationError


class TaxonomyTests(unittest.TestCase):
    def test_exact_85_class_contract(self) -> None:
        taxonomy = load_and_validate_taxonomy(TAXONOMY)
        self.assertEqual(85, len(taxonomy.classes))
        self.assertEqual(list(range(1, 86)), [item["class_number"] for item in taxonomy.classes])
        self.assertEqual(EXPECTED_ALWAYS, taxonomy.always_applicable)
        self.assertEqual(EXPECTED_ABSENCE, taxonomy.absence_classes)
        self.assertEqual(EXPECTED_LOGIC, taxonomy.logic_classes)

    def test_llm_agentic_content_carriers_are_complete(self) -> None:
        taxonomy = load_and_validate_taxonomy(TAXONOMY)
        rules = taxonomy.carrier_rules["llm_agentic"]
        self.assertEqual(list(range(66, 86)), rules["content_activates_classes"])
        for glob in ("**/SKILL.md", "**/*.prompt", "**/.cursorrules", "**/*mcp*.json", "**/*tool*.json"):
            self.assertIn(glob, rules["content_globs"])

    def test_hydra_and_mobile_rules_are_exact(self) -> None:
        taxonomy = load_and_validate_taxonomy(TAXONOMY)
        hydra = taxonomy.carrier_rules["hydra"]
        self.assertEqual(EXPECTED_BUILDERS, frozenset(hydra["approved_builders"]))
        self.assertEqual(list(range(22, 28)), [item["id"] for item in hydra["checks"]])
        self.assertEqual(["8", "11"], hydra["eol"]["java"]["flag"])
        self.assertEqual(["16", "18"], hydra["eol"]["node"]["flag"])
        self.assertEqual([f"M{number}" for number in range(1, 11)], [item["id"] for item in taxonomy.carrier_rules["mobile"]["mast"]])

    def test_duplicate_or_changed_mapping_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            bundle = Path(name) / "taxonomy"
            shutil.copytree(TAXONOMY.parent, bundle)
            taxonomy_path = bundle / "hunter_all_85.json"
            raw = json.loads(taxonomy_path.read_text(encoding="utf-8"))
            raw["classes"][10]["class_number"] = 10
            taxonomy_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(TaxonomyValidationError):
                load_and_validate_taxonomy(taxonomy_path)


if __name__ == "__main__":
    unittest.main()
