"""Deterministically group findings by compatible runtime environment."""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError
from hunter_managed_scan.models.validation import ValidationPack

MAX_FINDINGS_PER_PACK = 6

EXTENSION_FAMILIES = {
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".js": "node",
    ".jsx": "node",
    ".mjs": "node",
    ".cjs": "node",
    ".ts": "node",
    ".tsx": "node",
    ".py": "python",
    ".cs": "dotnet",
    ".fs": "dotnet",
    ".go": "go",
    ".swift": "mobile",
    ".dart": "mobile",
}


def environment_family(finding: dict[str, Any]) -> str:
    category = " ".join(
        str(finding.get(key, "")) for key in ("category", "class_name", "title", "description")
    ).lower()
    paths = [str(item["file"]).lower() for item in finding["affected_instances"]]
    joined = " ".join(paths)
    if any(token in category + " " + joined for token in ("llm", "agentic", "prompt", "model sdk", "mcp")):
        return "llm-agentic"
    if any(token in joined for token in (".github/workflows/", ".gitlab-ci", "jenkinsfile")) or "ci/cd" in category:
        return "ci-cd"
    if any(token in joined for token in ("dockerfile", "kubernetes", "helm/", ".tf", ".yaml", ".yml")) and any(
        token in category + " " + joined for token in ("container", "kubernetes", "terraform", "infrastructure", "docker")
    ):
        return "container-iac"
    if any(token in joined for token in ("androidmanifest.xml", "build.gradle", ".xcodeproj", "ios/", "android/")):
        return "mobile"
    families = {EXTENSION_FAMILIES.get(PurePosixPath(path).suffix) for path in paths}
    families.discard(None)
    if len(families) == 1:
        return families.pop()  # type: ignore[return-value]
    if len(families) > 1:
        return "multi-" + "-".join(sorted(families))
    return "generic"


def create_validation_packs(
    *,
    run_id: str,
    target_repository: str,
    target_commit: str,
    findings: list[dict[str, Any]],
    maximum_children: int = 5,
    maximum_acu: int = 7,
) -> list[ValidationPack]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in sorted(findings, key=lambda item: item["finding_id"]):
        grouped[environment_family(finding)].append(finding)
    requested = sum((len(items) + MAX_FINDINGS_PER_PACK - 1) // MAX_FINDINGS_PER_PACK for items in grouped.values())
    if requested > maximum_children:
        raise IncompleteCoverageError(
            f"compatible validation grouping requires {requested} children, above configured maximum {maximum_children}"
        )
    packs: list[ValidationPack] = []
    for family in sorted(grouped):
        findings_for_family = grouped[family]
        for index in range(0, len(findings_for_family), MAX_FINDINGS_PER_PACK):
            chunk = findings_for_family[index : index + MAX_FINDINGS_PER_PACK]
            number = (index // MAX_FINDINGS_PER_PACK) + 1
            pack_id = f"validator-{family}-{number}"
            packs.append(
                ValidationPack(
                    run_id=run_id,
                    pack_id=pack_id,
                    target_repository=target_repository,
                    target_commit=target_commit,
                    environment_family=family,
                    finding_ids=tuple(item["finding_id"] for item in chunk),
                    setup_plan=(
                        f"Initialize one isolated {family} test environment without changing the target repository",
                        "Execute a meaningful proof and a control for each assigned finding",
                        "Write one sanitized validation record per finding",
                    ),
                    build_once=True,
                    maximum_acu=maximum_acu,
                    result_branch=f"hunter-run/{run_id}/{pack_id}",
                )
            )
    return packs
