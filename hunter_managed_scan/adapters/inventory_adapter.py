"""Run and read the existing deterministic preparation pipeline exactly once."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import _accelerator  # noqa: F401
from hunter_accelerator.configuration import AcceleratorConfiguration
from hunter_accelerator.pipeline import run_pipeline
from hunter_accelerator.taxonomy import load_and_validate_taxonomy

from hunter_managed_scan.errors import OperationalError


def run_deterministic_preparation(
    target_repo_path: Path,
    output_dir: Path,
    cache_dir: Path,
    taxonomy_file: Path,
) -> tuple[str, dict[str, Any]]:
    taxonomy = load_and_validate_taxonomy(taxonomy_file)
    configuration = AcceleratorConfiguration(
        target_repo=target_repo_path,
        output_dir=output_dir,
        taxonomy_path=taxonomy.source_path,
        cache_dir=cache_dir,
        use_cache=True,
        strict=False,
    )
    return run_pipeline(configuration)


def load_json_artifact(output_dir: Path, name: str) -> Any:
    path = output_dir / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationalError(f"cannot read accelerator artifact {path}") from exc


def load_inventory(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / "file-inventory.jsonl"
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationalError(f"cannot read accelerator inventory {path}") from exc


def load_preparation_bundle(output_dir: Path) -> dict[str, Any]:
    return {
        "inventory": load_inventory(output_dir),
        "skipped": load_json_artifact(output_dir, "skipped-files.json"),
        "carriers": load_json_artifact(output_dir, "carrier-inventory.json"),
        "applicability": load_json_artifact(output_dir, "category-applicability.json"),
        "negative_evidence": load_json_artifact(output_dir, "negative-evidence.json"),
        "matchers": load_json_artifact(output_dir, "mandatory-matchers.json"),
        "logic_targets": load_json_artifact(output_dir, "logic-targets.json"),
        "unsupported": load_json_artifact(output_dir, "unsupported-constructs.json"),
        "coverage_gaps": load_json_artifact(output_dir, "coverage-gaps.json"),
        "profile": load_json_artifact(output_dir, "repository-profile.json"),
        "telemetry": load_json_artifact(output_dir, "telemetry.json"),
        "manifest": load_json_artifact(output_dir, "manifest.json"),
    }
