from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from hunter_accelerator.configuration import AcceleratorConfiguration
from hunter_accelerator.pipeline import run_pipeline

TAXONOMY = ROOT / "taxonomy" / "hunter_all_85.json"
FIXTURES = ROOT / "fixtures"


def run_repository(target: Path, *, use_cache: bool = False, max_file_size: int = 2 * 1024 * 1024, max_total_bytes: int = 128 * 1024 * 1024, cache_dir: Path | None = None) -> tuple[str, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="hunter-output-") as output_name:
        cache_context = tempfile.TemporaryDirectory(prefix="hunter-cache-") if cache_dir is None else None
        selected_cache = cache_dir or Path(cache_context.name)
        try:
            configuration = AcceleratorConfiguration(
                target_repo=target,
                output_dir=Path(output_name),
                taxonomy_path=TAXONOMY,
                max_file_size=max_file_size,
                max_total_bytes=max_total_bytes,
                cache_dir=selected_cache,
                use_cache=use_cache,
            )
            status, result = run_pipeline(configuration)
            artifacts: dict[str, Any] = {}
            for path in Path(output_name).iterdir():
                if path.suffix == ".json":
                    artifacts[path.name] = json.loads(path.read_text(encoding="utf-8"))
                elif path.suffix == ".jsonl":
                    artifacts[path.name] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            artifacts["pipeline_result"] = result
            return status, artifacts
        finally:
            if cache_context is not None:
                cache_context.cleanup()


def tree_digest(root: Path) -> dict[str, bytes | str]:
    result: dict[str, bytes | str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = f"symlink:{path.readlink()}"
        elif path.is_file():
            result[relative] = path.read_bytes()
    return result
