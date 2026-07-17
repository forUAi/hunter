#!/usr/bin/env python3
"""Direct, installation-free entry point for Hunter All deterministic preparation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from hunter_accelerator.configuration import (  # noqa: E402
    DEFAULT_CACHE_DIR,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_OUTPUT_DIR,
    AcceleratorConfiguration,
)
from hunter_accelerator.errors import AcceleratorError, TaxonomyValidationError, WorkspaceSafetyError  # noqa: E402
from hunter_accelerator.evidence import redact_text  # noqa: E402
from hunter_accelerator.pipeline import run_pipeline  # noqa: E402


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"devin_prepare.py: error: {redact_text(message)}", file=sys.stderr)
        raise SystemExit(4)


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(description="Deterministic, read-only Hunter All Phase 1 preparation")
    parser.add_argument("--target-repo", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--taxonomy", type=Path, default=SCRIPT_ROOT / "taxonomy" / "hunter_all_85.json")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--summary-only", action="store_true")
    return parser


def _print_summary(status: str, result: dict[str, object], summary_only: bool) -> None:
    summary = result["summary"]
    assert isinstance(summary, dict)
    output_dir = str(result["output_dir"])
    print(f"Hunter Accelerator: {status}")
    if summary_only:
        print(f"Artifacts: {output_dir}/manifest.json")
        return
    print(f"Repository types: {', '.join(summary['repository_types'])}")
    print(f"Files inventoried: {summary['files_inventoried']}")
    print(f"Applicable classes: {summary['applicable_category_count']}")
    print(f"N/A with negative evidence: {summary['not_applicable_count']}")
    print(f"Unresolved classes: {summary['unresolved_category_count']}")
    print(f"Matchers generated: {summary['mandatory_matcher_count']}")
    print(f"Logic targets: {summary['logic_target_count']}")
    print(f"Coverage gaps: {summary['coverage_gap_count']}")
    print(f"Artifacts: {output_dir}/manifest.json")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configuration = AcceleratorConfiguration(
        target_repo=args.target_repo,
        output_dir=args.output_dir,
        taxonomy_path=args.taxonomy,
        max_file_size=args.max_file_size,
        max_total_bytes=args.max_total_bytes,
        cache_dir=args.cache_dir,
        use_cache=not args.no_cache,
        strict=args.strict,
        summary_only=args.summary_only,
    )
    try:
        status, result = run_pipeline(configuration)
    except ValueError as exc:
        print(f"Hunter Accelerator: invalid invocation: {redact_text(str(exc))}", file=sys.stderr)
        return 4
    except WorkspaceSafetyError as exc:
        print(f"Hunter Accelerator: invalid invocation: {redact_text(str(exc))}", file=sys.stderr)
        return 4
    except TaxonomyValidationError as exc:
        print(f"Hunter Accelerator: FAILED: {redact_text(str(exc))}", file=sys.stderr)
        return 3
    except (AcceleratorError, OSError, json.JSONDecodeError) as exc:
        print(f"Hunter Accelerator: FAILED: {redact_text(str(exc))}", file=sys.stderr)
        return 3
    except Exception as exc:  # Last-resort sanitization for untrusted repository edge cases.
        print(f"Hunter Accelerator: FAILED: {redact_text(type(exc).__name__ + ': ' + str(exc))}", file=sys.stderr)
        return 3
    _print_summary(status, result, args.summary_only)
    return {"COMPLETE": 0, "PARTIAL": 2, "FAILED": 3}[status]


if __name__ == "__main__":
    raise SystemExit(main())
