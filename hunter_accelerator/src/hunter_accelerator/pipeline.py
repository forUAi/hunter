"""End-to-end deterministic preparation pipeline for the immutable Hunter All profile."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from .analyzer import AnalysisAccumulator, FileAnalyzer
from .applicability import decide_applicability
from .cache import AnalysisCache
from .carrier_detection import CarrierEvidence
from .configuration import AcceleratorConfiguration
from .coverage import evaluate_coverage
from .file_inventory import FileInventoryBuilder
from .hashing import stable_json_hash
from .matcher_generation import generate_matchers
from .negative_evidence import build_negative_evidence
from .output import ARTIFACT_NAMES, write_artifacts, write_manifest
from .taxonomy import load_and_validate_taxonomy
from .telemetry import Telemetry
from .workspace import RepositoryWorkspace


def _repository_profile(
    repository: Any,
    records: list[Any],
    skipped: list[Any],
    accumulator: AnalysisAccumulator,
) -> dict[str, Any]:
    carrier_types = {item.carrier_type for item in accumulator.carriers}
    paths = [record.relative_path for record in records]
    ci_systems: set[str] = set()
    if any(path.startswith(".github/workflows/") for path in paths):
        ci_systems.add("GitHub Actions")
    if any(Path(path).name.lower().startswith("jenkinsfile") for path in paths):
        ci_systems.add("Jenkins")
    if ".gitlab-ci.yml" in paths:
        ci_systems.add("GitLab CI")
    if ".circleci/config.yml" in paths:
        ci_systems.add("CircleCI")
    if "azure-pipelines.yml" in paths:
        ci_systems.add("Azure Pipelines")
    repository_types: set[str] = set()
    if "HTTP/API route" in carrier_types:
        repository_types.add("web/API application")
    if carrier_types & {"container", "Kubernetes", "Helm", "Terraform/IaC", "cloud configuration"}:
        repository_types.add("infrastructure/deployment")
    if carrier_types & {"mobile", "binary mobile"}:
        repository_types.add("mobile")
    if "CI/CD" in carrier_types:
        repository_types.add("CI/CD automation")
    if carrier_types & {"LLM SDK", "prompt or instruction", "agent tool", "MCP", "agent memory"}:
        repository_types.add("LLM/agentic")
    if not repository_types:
        repository_types.add("source/library")

    capabilities = accumulator.capabilities
    mobile_technologies = sorted(
        set(capabilities.get("mobile_technologies", set()))
        | {framework for record in records for framework in record.framework_hints if framework in {"React Native", "Flutter"}}
        | ({"Android"} if any("android" in path.lower() or path.endswith("AndroidManifest.xml") for path in paths) else set())
        | ({"iOS"} if any(Path(path).suffix.lower() in {".swift", ".m", ".mm", ".plist"} for path in paths) else set())
    )
    return {
        "repository_id": repository.repository_id,
        "repository_name": repository.name,
        "target_repository": repository.absolute_path,
        "commit_sha": repository.commit_sha,
        "working_tree_status": repository.working_tree_state,
        "has_git_history": repository.has_git_history,
        "git_metadata_status": repository.git_metadata_status,
        "git_metadata_reason": repository.git_metadata_reason,
        "file_count": len(records),
        "text_file_count": sum(not record.binary for record in records),
        "binary_file_count": sum(record.binary for record in records),
        "skipped_file_count": len(skipped),
        "languages": sorted({language for record in records for language in record.language_hints}),
        "frameworks": sorted({framework for record in records for framework in record.framework_hints}),
        "build_systems": sorted(accumulator.build_systems),
        "package_managers": sorted(accumulator.package_managers),
        "database_technologies": sorted(capabilities.get("database_technologies", set())),
        "orms_and_data_clients": sorted(capabilities.get("orms_and_data_clients", set())),
        "http_api_frameworks": sorted(
            {framework for record in records for framework in record.framework_hints if framework not in {"React", "Angular", "React Native", "Flutter"}}
        ),
        "authentication_technologies": sorted(capabilities.get("authentication_technologies", set())),
        "authorization_technologies": sorted(capabilities.get("authorization_technologies", set())),
        "logging_technologies": sorted(capabilities.get("logging_technologies", set())),
        "cryptographic_technologies": sorted(capabilities.get("cryptographic_technologies", set())),
        "outbound_http_clients": sorted(capabilities.get("outbound_http_clients", set())),
        "file_archive_operations": sorted(capabilities.get("file_archive_operations", set())),
        "ci_cd_systems": sorted(ci_systems),
        "container_technologies": sorted(carrier_types & {"container", "Kubernetes", "Helm", "container CI/CD"}),
        "iac_technologies": sorted(carrier_types & {"Terraform/IaC", "Kubernetes", "Helm"}),
        "cloud_technologies": sorted(capabilities.get("cloud_technologies", set())),
        "mobile_technologies": mobile_technologies,
        "llm_technologies": sorted(capabilities.get("llm_technologies", set())),
        "agent_technologies": sorted(capabilities.get("agent_technologies", set())),
        "prompt_and_instruction_carriers": sorted(
            {item.file for item in accumulator.carriers if item.carrier_type == "prompt or instruction"}
        ),
        "vector_and_embedding_technologies": sorted(capabilities.get("vector_and_embedding_technologies", set())),
        "internal_framework_indicators": sorted(capabilities.get("internal_framework_indicators", set())),
        "unsupported_constructs": [item.as_json() for item in accumulator.unsupported],
        "repository_types": sorted(repository_types),
    }


def run_pipeline(configuration: AcceleratorConfiguration) -> tuple[str, dict[str, Any]]:
    configuration.validate_numbers()
    started_at = datetime.now(timezone.utc).isoformat()
    started_monotonic = monotonic()
    workspace = RepositoryWorkspace(configuration.target_repo, configuration.output_dir, configuration.cache_dir)
    taxonomy = load_and_validate_taxonomy(configuration.taxonomy_path)
    repository = workspace.repository_info()
    telemetry = Telemetry()
    analyzer = FileAnalyzer(taxonomy)
    accumulator = AnalysisAccumulator()
    cache = AnalysisCache(
        workspace.cache_dir,
        repository.absolute_path,
        taxonomy.version,
        configuration.accelerator_version,
        configuration.configuration_version,
        repository.commit_sha,
        repository.working_tree_state,
        configuration.use_cache,
    )
    inventory = FileInventoryBuilder(workspace, configuration.max_file_size, configuration.max_total_bytes)

    def process(record: Any, text: str | None) -> None:
        cached = cache.load(record)
        if cached is not None:
            telemetry.metrics.cache_hits += 1
            analysis = cached
        else:
            if configuration.use_cache:
                telemetry.metrics.cache_misses += 1
            analysis = analyzer.analyze(record, text)
            telemetry.metrics.regex_searches += analysis.regex_searches
            cache.store(record, analysis)
        accumulator.add(analysis)

    with telemetry.phase("inventory"):
        records, skipped = inventory.scan(process)
    telemetry.metrics.files_scanned = len(records)
    telemetry.metrics.bytes_scanned = inventory.bytes_scanned
    accumulator.finalize()
    telemetry.metrics.phase_seconds["carrier_analysis"] = telemetry.metrics.phase_seconds.get("inventory", 0.0)
    telemetry.metrics.phase_seconds["logic_targets"] = telemetry.metrics.phase_seconds.get("inventory", 0.0)

    if repository.has_git_history:
        accumulator.carriers.append(
            CarrierEvidence(
                carrier_type="git history",
                file=".git",
                line=None,
                classes_activated=(24,),
                evidence="Git history is available for downstream Class 24 review",
                discovery_method="read-only git metadata",
                confidence="HIGH",
            )
        )
        accumulator.carriers.sort(key=lambda item: (item.carrier_type, item.file, item.line or 0))

    with telemetry.phase("applicability"):
        decisions = decide_applicability(
            taxonomy,
            records,
            skipped,
            accumulator.carriers,
            accumulator.unsupported,
            accumulator.negative_matches,
            repository.has_git_history,
            repository.git_metadata_status,
        )
        negative_evidence = build_negative_evidence(taxonomy, decisions, skipped)
    with telemetry.phase("matcher_generation"):
        matchers = generate_matchers(taxonomy, decisions)
    with telemetry.phase("coverage"):
        gaps = evaluate_coverage(
            taxonomy,
            decisions,
            matchers,
            accumulator.logic_targets,
            accumulator.carriers,
            skipped,
            accumulator.unsupported,
            repository.git_metadata_status,
            repository.git_metadata_reason,
        )
    telemetry.metrics.coverage_gaps = len(gaps)
    status = "COMPLETE" if not gaps and not accumulator.unsupported else "PARTIAL"
    if configuration.strict and status == "PARTIAL":
        status = "FAILED"

    profile = _repository_profile(repository, records, skipped, accumulator)
    status_counts = Counter(item["status"] for item in decisions)
    cache_status = (
        "DISABLED"
        if not configuration.use_cache
        else "HIT"
        if records and telemetry.metrics.cache_hits == len(records)
        else "PARTIAL_HIT"
        if telemetry.metrics.cache_hits
        else "MISS"
    )
    telemetry_data = telemetry.as_json()
    summary = {
        "languages": profile["languages"],
        "frameworks": profile["frameworks"],
        "repository_types": profile["repository_types"],
        "applicable_category_count": status_counts["ALWAYS_APPLICABLE"] + status_counts["APPLICABLE"],
        "not_applicable_count": status_counts["NOT_APPLICABLE_WITH_NEGATIVE_EVIDENCE"],
        "unresolved_category_count": status_counts["UNRESOLVED"],
        "mandatory_matcher_count": len(matchers),
        "logic_target_count": len(accumulator.logic_targets),
        "coverage_gap_count": len(gaps),
        "unsupported_construct_count": len(accumulator.unsupported),
        "files_inventoried": len(records),
        "files_skipped": len(skipped),
        "runtime_seconds": telemetry_data["total_runtime_seconds"],
        "cache_status": cache_status,
        "overall_status": status,
        "phase_1_scope": "deterministic preparation only; Hunter All remains final authority",
    }
    artifacts: dict[str, Any] = {
        "summary.json": summary,
        "repository-profile.json": profile,
        "skipped-files.json": [entry.as_json() for entry in skipped],
        "carrier-inventory.json": [item.as_json() for item in accumulator.carriers],
        "category-applicability.json": decisions,
        "negative-evidence.json": negative_evidence,
        "mandatory-matchers.json": matchers,
        "logic-targets.json": [item.as_json() for item in accumulator.logic_targets],
        "unsupported-constructs.json": [item.as_json() for item in accumulator.unsupported],
        "coverage-gaps.json": gaps,
        "telemetry.json": telemetry_data,
        "errors.json": [],
    }
    hashes = write_artifacts(workspace.output_dir, artifacts, [record.as_json() for record in records])
    ended_at = datetime.now(timezone.utc).isoformat()
    artifact_paths = {name: name for name in ARTIFACT_NAMES}
    manifest = {
        "accelerator_version": configuration.accelerator_version,
        "taxonomy_version": taxonomy.version,
        "profile_id": taxonomy.profile_id,
        "target_repository": repository.absolute_path,
        "commit_sha": repository.commit_sha,
        "working_tree_state": repository.working_tree_state,
        "git_metadata_status": repository.git_metadata_status,
        "git_metadata_reason": repository.git_metadata_reason,
        "file_manifest_hash": inventory.manifest_hash,
        "cache_key_inputs_hash": stable_json_hash(
            {
                "target_repository_absolute_path": repository.absolute_path,
                "commit_sha": repository.commit_sha,
                "working_tree_state": repository.working_tree_state,
                "working_tree_file_hashes": [record.content_hash for record in records],
                "taxonomy_version": taxonomy.version,
                "accelerator_version": configuration.accelerator_version,
                "configuration_version": configuration.configuration_version,
            }
        ),
        "start_time": started_at,
        "end_time": ended_at,
        "runtime_seconds": round(monotonic() - started_monotonic, 6),
        "status": status,
        "artifact_paths": artifact_paths,
        "artifact_hashes": hashes,
        "coverage_gap_count": len(gaps),
        "unsupported_construct_count": len(accumulator.unsupported),
    }
    write_manifest(workspace.output_dir, manifest)
    result = {"summary": summary, "manifest": manifest, "output_dir": str(workspace.output_dir)}
    return status, result
