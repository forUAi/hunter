"""Group findings by concrete runtime, module, service, and configuration compatibility."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

from hunter_managed_scan.errors import IncompleteCoverageError
from hunter_managed_scan.models.validation import ValidationPack

MAX_FINDINGS_PER_PACK = 6
MANIFEST_NAMES = {
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "build.gradle.kts": ("java", "gradle"),
    "package.json": ("node", "npm"),
    "pnpm-lock.yaml": ("node", "pnpm"),
    "yarn.lock": ("node", "yarn"),
    "pyproject.toml": ("python", "python-project"),
    "requirements.txt": ("python", "pip"),
    "go.mod": ("go", "go-modules"),
    "packages.lock.json": ("dotnet", "nuget"),
    "pubspec.yaml": ("mobile", "dart-pub"),
    "podfile": ("mobile", "cocoapods"),
    "chart.yaml": ("configuration", "helm"),
}
EXTENSION_FAMILIES = {
    ".java": "java", ".kt": "java", ".kts": "java",
    ".js": "node", ".jsx": "node", ".mjs": "node", ".cjs": "node", ".ts": "node", ".tsx": "node",
    ".py": "python", ".cs": "dotnet", ".fs": "dotnet", ".go": "go", ".swift": "mobile", ".dart": "mobile",
}


def _common_text(finding: dict[str, Any]) -> str:
    values = [finding.get(key, "") for key in ("category", "class_name", "title", "description", "source", "sink")]
    values.extend(finding.get("evidence", []))
    return " ".join(str(value) for value in values).lower()


def _runtime_family(paths: list[str], text: str) -> str:
    joined = " ".join(paths).lower()
    if ".github/workflows/" in joined or "github actions" in text or "ci/cd" in text:
        return "ci-cd"
    if any(path.endswith(".tf") for path in paths) or "terraform" in text:
        return "terraform"
    if any("chart.yaml" in path.lower() or "/templates/" in path.lower() for path in paths) and "helm" in text + joined:
        return "helm"
    if any(token in text + joined for token in ("llm", "agentic", "prompt", "model sdk", "mcp")):
        return "llm-agentic"
    if any(token in joined for token in ("androidmanifest.xml", ".xcodeproj", "ios/", "android/")):
        return "mobile"
    families = {EXTENSION_FAMILIES.get(PurePosixPath(path).suffix.lower()) for path in paths}
    families.discard(None)
    if len(families) == 1:
        return str(next(iter(families)))
    if len(families) > 1:
        return "multi-" + "-".join(sorted(str(value) for value in families))
    return "generic"


def _nearest_manifests(file_path: str, inventory_paths: set[str]) -> list[str]:
    path = PurePosixPath(file_path)
    candidates: list[tuple[int, str]] = []
    for manifest in inventory_paths:
        manifest_path = PurePosixPath(manifest)
        name = manifest_path.name.lower()
        if name not in MANIFEST_NAMES:
            continue
        try:
            path.relative_to(manifest_path.parent)
        except ValueError:
            continue
        candidates.append((len(manifest_path.parent.parts), manifest))
    if not candidates:
        return []
    maximum_depth = max(depth for depth, _manifest in candidates)
    return sorted(manifest for depth, manifest in candidates if depth == maximum_depth)


def _framework(text: str) -> str:
    for framework in ("spring", "quarkus", "micronaut", "express", "nestjs", "nextjs", "react", "django", "flask", "fastapi", "asp.net", "gin"):
        if framework in text:
            return framework
    return "unspecified"


def _runtime_version(text: str, family: str) -> str:
    patterns = {
        "java": r"\b(?:java|jdk)\s*[-:=]?\s*(\d{1,2})\b",
        "node": r"\bnode(?:js)?\s*[-:=]?\s*v?(\d{1,2}(?:\.\d+)*)\b",
        "python": r"\bpython\s*[-:=]?\s*(3(?:\.\d+){0,2})\b",
        "go": r"\bgo\s*[-:=]?\s*(1\.\d+(?:\.\d+)?)\b",
    }
    match = re.search(patterns.get(family, r"(?!)"), text)
    return match.group(1) if match else "unspecified"


def compatibility_key(
    finding: dict[str, Any], inventory: list[dict[str, Any]] | list[str] | None = None
) -> dict[str, str]:
    paths = sorted(str(item["file"]) for item in finding["affected_instances"])
    inventory_paths = {
        str(item["relative_path"] if isinstance(item, dict) else item) for item in (inventory or [])
    }
    text = _common_text(finding)
    family = _runtime_family(paths, text)
    joined = " ".join(paths).lower()
    if family == "ci-cd":
        return {
            "runtime_family": family, "runtime_version": "github-hosted",
            "module_root": ".github/workflows", "service_boundary": "repository-ci",
            "package_manager": "github-actions", "build_manifest": ".github/workflows",
            "framework": "github-actions", "configuration_type": "github-actions",
        }
    if family == "terraform":
        roots = sorted({str(PurePosixPath(path).parent) or "." for path in paths})
        root = roots[0] if len(roots) == 1 else "multi:" + ",".join(roots)
        return {
            "runtime_family": family, "runtime_version": _runtime_version(text, family),
            "module_root": root, "service_boundary": root, "package_manager": "terraform",
            "build_manifest": root, "framework": "terraform", "configuration_type": "terraform",
        }
    if family == "helm":
        roots = sorted({str(PurePosixPath(path).parent) or "." for path in paths})
        root = roots[0] if len(roots) == 1 else "multi:" + ",".join(roots)
        return {
            "runtime_family": family, "runtime_version": "unspecified", "module_root": root,
            "service_boundary": root, "package_manager": "helm", "build_manifest": f"{root}/Chart.yaml",
            "framework": "helm", "configuration_type": "helm",
        }
    manifests = sorted({manifest for path in paths for manifest in _nearest_manifests(path, inventory_paths)})
    if manifests:
        roots = sorted({str(PurePosixPath(manifest).parent) or "." for manifest in manifests})
        managers = sorted({MANIFEST_NAMES[PurePosixPath(manifest).name.lower()][1] for manifest in manifests})
        manifest_value = manifests[0] if len(manifests) == 1 else "multi:" + ",".join(manifests)
        root = roots[0] if len(roots) == 1 else "multi:" + ",".join(roots)
        manager = managers[0] if len(managers) == 1 else "multi:" + ",".join(managers)
    else:
        root = "."
        manager = "unspecified"
        manifest_value = "unspecified"
    components = sorted({str(item.get("component", "unspecified")) for item in finding["affected_instances"]})
    boundary = root if root != "." else (components[0] if len(components) == 1 else "multi:" + ",".join(components))
    configuration_type = "application"
    if "kubernetes" in text + joined:
        configuration_type = "kubernetes"
    return {
        "runtime_family": family,
        "runtime_version": _runtime_version(text, family),
        "module_root": root,
        "service_boundary": boundary,
        "package_manager": manager,
        "build_manifest": manifest_value,
        "framework": _framework(text),
        "configuration_type": configuration_type,
    }


def environment_family(finding: dict[str, Any]) -> str:
    """Backward-compatible accessor used by callers that only need the family."""
    return compatibility_key(finding)["runtime_family"]


def create_validation_packs(
    *, run_id: str, target_repository: str, target_commit: str,
    findings: list[dict[str, Any]], inventory: list[dict[str, Any]] | list[str] | None = None,
    maximum_children: int = 5, maximum_acu: int = 7,
) -> list[ValidationPack]:
    grouped: dict[tuple[tuple[str, str], ...], list[dict[str, Any]]] = defaultdict(list)
    keys: dict[tuple[tuple[str, str], ...], dict[str, str]] = {}
    for finding in sorted(findings, key=lambda item: item["finding_id"]):
        key = compatibility_key(finding, inventory)
        frozen = tuple(sorted(key.items()))
        keys[frozen] = key
        grouped[frozen].append(finding)
    requested = sum((len(items) + MAX_FINDINGS_PER_PACK - 1) // MAX_FINDINGS_PER_PACK for items in grouped.values())
    if requested > maximum_children:
        raise IncompleteCoverageError(
            f"compatible validation grouping requires {requested} children, above configured maximum {maximum_children}"
        )
    packs: list[ValidationPack] = []
    family_counts: dict[str, int] = defaultdict(int)
    for frozen in sorted(grouped):
        key = keys[frozen]
        family = key["runtime_family"]
        items = grouped[frozen]
        for offset in range(0, len(items), MAX_FINDINGS_PER_PACK):
            family_counts[family] += 1
            pack_id = f"validator-{family}-{family_counts[family]}"
            chunk = items[offset : offset + MAX_FINDINGS_PER_PACK]
            packs.append(
                ValidationPack(
                    run_id=run_id, pack_id=pack_id, target_repository=target_repository,
                    target_commit=target_commit, environment_family=family, compatibility_key=key,
                    finding_ids=tuple(item["finding_id"] for item in chunk),
                    setup_plan=(
                        f"Initialize isolated {family} environment for module {key['module_root']}",
                        f"Use build manifest {key['build_manifest']} and package manager {key['package_manager']}",
                        "Execute one evidence-bound proof and explicit control for each finding",
                    ),
                    build_once=True, maximum_acu=maximum_acu,
                    result_branch=f"hunter-run/{run_id}/{pack_id}",
                )
            )
    return sorted(packs, key=lambda item: item.pack_id)
