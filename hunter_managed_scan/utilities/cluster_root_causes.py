"""Exact mechanical deduplication plus non-authoritative cluster suggestions."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from hunter_managed_scan.utilities.json_io import read_json, write_json
from hunter_managed_scan.utilities.audit_log import AuditLog


def _instance_key(instance: dict[str, Any]) -> tuple[Any, ...]:
    return (
        instance["file"],
        instance["start_line"],
        instance["end_line"],
        instance["excerpt_sha256"],
        instance["component"],
        instance["endpoint_or_workflow"],
    )


def _exact_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    evidence_locations = tuple(
        sorted((item["file"], item["start_line"], item["end_line"]) for item in finding["affected_instances"])
    )
    workflows = tuple(sorted(item["endpoint_or_workflow"] for item in finding["affected_instances"]))
    return (
        finding["class_number"],
        finding["security_property"],
        finding["root_cause_candidate"],
        finding["sink"],
        tuple(finding["attack_path"]),
        evidence_locations,
        workflows,
    )


def cluster_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge only exact duplicates and suggest broader groups for human review."""

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for finding in sorted(findings, key=lambda item: item["finding_id"]):
        groups.setdefault(_exact_key(finding), []).append(finding)

    merged: list[dict[str, Any]] = []
    exact_groups: list[dict[str, Any]] = []
    for members in groups.values():
        representative = deepcopy(members[0])
        instances: dict[tuple[Any, ...], dict[str, Any]] = {}
        for member in members:
            for instance in member["affected_instances"]:
                instances[_instance_key(instance)] = deepcopy(instance)
        representative["affected_instances"] = [instances[key] for key in sorted(instances)]
        merged.append(representative)
        if len(members) > 1:
            exact_groups.append(
                {
                    "representative_finding_id": representative["finding_id"],
                    "merged_finding_ids": [item["finding_id"] for item in members[1:]],
                    "affected_instance_count": len(instances),
                }
            )

    candidates: dict[tuple[Any, ...], list[str]] = {}
    for finding in merged:
        key = (finding["class_number"], finding["security_property"], finding["root_cause_candidate"])
        candidates.setdefault(key, []).append(finding["finding_id"])
    suggestions = [
        {
            "class_number": key[0],
            "security_property": key[1],
            "root_cause_candidate": key[2],
            "finding_ids": sorted(ids),
            "action": "PARENT_REVIEW_REQUIRED",
        }
        for key, ids in sorted(candidates.items())
        if len(ids) > 1
    ]
    return {
        "schema_version": 1,
        "findings": sorted(merged, key=lambda item: item["finding_id"]),
        "exact_duplicate_groups": sorted(exact_groups, key=lambda item: item["representative_finding_id"]),
        "root_cause_suggestions": suggestions,
    }


def cluster_run_findings(run_dir: Path) -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    findings = read_json(run_dir / "investigation" / "normalized" / "findings.json")
    result = cluster_findings(findings)
    write_json(run_dir / "root-causes" / "clusters.json", result)
    write_json(run_dir / "root-causes" / "findings-clustered.json", result["findings"])
    AuditLog(run_dir / "audit-log.jsonl").append(
        "root_cause_clustering",
        run_id=str(manifest["run_id"]),
        details={
            "input_findings": len(findings),
            "output_findings": len(result["findings"]),
            "exact_duplicate_groups": len(result["exact_duplicate_groups"]),
            "suggestions": len(result["root_cause_suggestions"]),
        },
    )
    return result
