"""Small standard-library data models used by the Phase 1 pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RepositoryInfo:
    repository_id: str
    name: str
    absolute_path: str
    commit_sha: str | None
    working_tree_state: str
    has_git_history: bool
    git_metadata_status: str = "not_git"
    git_metadata_reason: str | None = None


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    extension: str
    size: int
    content_hash: str
    binary: bool
    generated: bool
    test: bool
    configuration: bool
    source_code: bool
    prompt_content: bool
    ci_cd: bool
    container_iac: bool
    mobile: bool
    dependency_manifest: bool
    security_relevant: bool
    vendor_derived: bool = False
    language_hints: tuple[str, ...] = ()
    framework_hints: tuple[str, ...] = ()
    line_count: int = 0
    encoding_errors: int = 0

    def as_json(self) -> dict[str, Any]:
        result = asdict(self)
        for name in ("language_hints", "framework_hints"):
            result[name] = list(result[name])
        result["binary_text_status"] = "binary" if self.binary else "text"
        return result


@dataclass(frozen=True)
class SkippedEntry:
    relative_path: str
    entry_type: str
    reason: str
    security_relevant: bool
    size: int | None = None
    carrier_hints: tuple[str, ...] = ()
    generated: bool = False
    vendor_derived: bool = False

    def as_json(self) -> dict[str, Any]:
        result = asdict(self)
        result["carrier_hints"] = list(self.carrier_hints)
        return result


@dataclass(frozen=True)
class CarrierEvidence:
    carrier_type: str
    file: str
    line: int | None
    classes_activated: tuple[int, ...]
    evidence: str
    discovery_method: str
    confidence: str

    def as_json(self) -> dict[str, Any]:
        from .hashing import stable_id

        result = asdict(self)
        result["classes_activated"] = list(self.classes_activated)
        result["carrier_id"] = stable_id(
            "carrier",
            self.carrier_type,
            self.file,
            self.line,
            self.evidence,
            length=20,
        )
        return result


@dataclass(frozen=True)
class LogicTarget:
    target_id: str
    file: str
    line_start: int
    line_end: int
    symbol: str
    activated_classes: tuple[int, ...]
    signals: tuple[str, ...]
    questions_for_devin: tuple[str, ...]
    confidence: str

    def as_json(self) -> dict[str, Any]:
        result = asdict(self)
        for name in ("activated_classes", "signals", "questions_for_devin"):
            result[name] = list(result[name])
        return result


@dataclass(frozen=True)
class UnsupportedConstruct:
    file: str
    symbol_or_section: str
    construct_type: str
    affected_categories: tuple[int, ...]
    reason: str
    recommended_devin_action: str
    completion_impact: str = "PARTIAL"

    def as_json(self) -> dict[str, Any]:
        from .hashing import stable_id

        result = asdict(self)
        result["affected_categories"] = list(self.affected_categories)
        result["construct_id"] = stable_id(
            "unsupported",
            self.file,
            self.symbol_or_section,
            self.construct_type,
            length=20,
        )
        return result


@dataclass
class ScanMetrics:
    start_monotonic: float
    phase_seconds: dict[str, float] = field(default_factory=dict)
    files_scanned: int = 0
    bytes_scanned: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    regex_searches: int = 0
    coverage_gaps: int = 0


@dataclass(frozen=True)
class FileAnalysis:
    """Serializable, content-addressed analysis produced while a file is read once."""

    capabilities: dict[str, tuple[str, ...]] = field(default_factory=dict)
    build_systems: tuple[str, ...] = ()
    package_managers: tuple[str, ...] = ()
    carriers: tuple[dict[str, Any], ...] = ()
    logic_targets: tuple[dict[str, Any], ...] = ()
    unsupported_constructs: tuple[dict[str, Any], ...] = ()
    negative_matches: dict[str, tuple[dict[str, Any], ...]] = field(default_factory=dict)
    regex_searches: int = 0

    def as_json(self) -> dict[str, Any]:
        return {
            "capabilities": {key: list(value) for key, value in sorted(self.capabilities.items())},
            "build_systems": list(self.build_systems),
            "package_managers": list(self.package_managers),
            "carriers": list(self.carriers),
            "logic_targets": list(self.logic_targets),
            "unsupported_constructs": list(self.unsupported_constructs),
            "negative_matches": {
                key: list(value) for key, value in sorted(self.negative_matches.items(), key=lambda item: int(item[0]))
            },
            "regex_searches": self.regex_searches,
        }

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> "FileAnalysis":
        return cls(
            capabilities={
                str(key): tuple(str(item) for item in items)
                for key, items in value.get("capabilities", {}).items()
                if isinstance(items, list)
            },
            build_systems=tuple(str(item) for item in value.get("build_systems", [])),
            package_managers=tuple(str(item) for item in value.get("package_managers", [])),
            carriers=tuple(item for item in value.get("carriers", []) if isinstance(item, dict)),
            logic_targets=tuple(item for item in value.get("logic_targets", []) if isinstance(item, dict)),
            unsupported_constructs=tuple(
                item for item in value.get("unsupported_constructs", []) if isinstance(item, dict)
            ),
            negative_matches={
                str(key): tuple(item for item in items if isinstance(item, dict))
                for key, items in value.get("negative_matches", {}).items()
                if isinstance(items, list)
            },
            regex_searches=int(value.get("regex_searches", 0)),
        )


@dataclass(frozen=True)
class TaxonomyBundle:
    source_path: Path
    version: str
    profile_id: str
    classes: tuple[dict[str, Any], ...]
    always_applicable: frozenset[int]
    absence_classes: frozenset[int]
    logic_classes: frozenset[int]
    carrier_rules: dict[str, Any]
    applicability_rules: dict[str, Any]

    @property
    def by_number(self) -> dict[int, dict[str, Any]]:
        return {item["class_number"]: item for item in self.classes}
