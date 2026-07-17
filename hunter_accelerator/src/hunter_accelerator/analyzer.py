"""Per-file Phase 1 analysis composed from deterministic standard-library detectors."""

from __future__ import annotations

from typing import Any

from .build_detection import detect_build
from .carrier_detection import CarrierDetector, carrier_from_json
from .dependency_detection import detect_capabilities
from .logic_targets import enumerate_logic_targets
from .models import CarrierEvidence, FileAnalysis, FileRecord, LogicTarget, TaxonomyBundle, UnsupportedConstruct
from .negative_evidence import NegativeEvidenceSearcher
from .unsupported import detect_unsupported


class FileAnalyzer:
    def __init__(self, taxonomy: TaxonomyBundle) -> None:
        self.carriers = CarrierDetector(taxonomy)
        self.negative = NegativeEvidenceSearcher(taxonomy)

    def analyze(self, record: FileRecord, text: str | None) -> FileAnalysis:
        capabilities = detect_capabilities(text or "") if text is not None else {}
        builds, managers = detect_build(record.relative_path)
        carriers = self.carriers.detect(record, text)
        targets = enumerate_logic_targets(record, text)
        unsupported = detect_unsupported(record, text)
        negative_matches, regex_searches = self.negative.search_file(record, text)
        return FileAnalysis(
            capabilities={key: tuple(sorted(value)) for key, value in capabilities.items() if value},
            build_systems=tuple(sorted(builds)),
            package_managers=tuple(sorted(managers)),
            carriers=tuple(item.as_json() for item in carriers),
            logic_targets=tuple(item.as_json() for item in targets),
            unsupported_constructs=tuple(item.as_json() for item in unsupported),
            negative_matches=negative_matches,
            regex_searches=regex_searches,
        )


class AnalysisAccumulator:
    def __init__(self) -> None:
        self.capabilities: dict[str, set[str]] = {}
        self.build_systems: set[str] = set()
        self.package_managers: set[str] = set()
        self.carriers: list[CarrierEvidence] = []
        self.logic_targets: list[LogicTarget] = []
        self.unsupported: list[UnsupportedConstruct] = []
        self.negative_matches: dict[int, list[dict[str, Any]]] = {}

    def add(self, analysis: FileAnalysis) -> None:
        for category, values in analysis.capabilities.items():
            self.capabilities.setdefault(category, set()).update(values)
        self.build_systems.update(analysis.build_systems)
        self.package_managers.update(analysis.package_managers)
        self.carriers.extend(carrier_from_json(item) for item in analysis.carriers)
        self.logic_targets.extend(_logic_target_from_json(item) for item in analysis.logic_targets)
        self.unsupported.extend(_unsupported_from_json(item) for item in analysis.unsupported_constructs)
        for number, values in analysis.negative_matches.items():
            self.negative_matches.setdefault(int(number), []).extend(values)

    def finalize(self) -> None:
        carrier_unique = {
            (item.carrier_type, item.file, item.line, item.evidence): item for item in self.carriers
        }
        self.carriers = [
            carrier_unique[key]
            for key in sorted(carrier_unique, key=lambda key: (key[0], key[1], key[2] or 0, key[3]))
        ]
        target_unique = {item.target_id: item for item in self.logic_targets}
        self.logic_targets = [
            target_unique[key]
            for key in sorted(target_unique, key=lambda key: (target_unique[key].file, target_unique[key].line_start, key))
        ]
        unsupported_unique = {
            (item.file, item.symbol_or_section, item.construct_type): item for item in self.unsupported
        }
        self.unsupported = [unsupported_unique[key] for key in sorted(unsupported_unique)]
        for number, values in self.negative_matches.items():
            unique = {(item["file"], item.get("line"), item["indicator"]): item for item in values}
            self.negative_matches[number] = [
                unique[key] for key in sorted(unique, key=lambda key: (key[0], key[1] or 0, key[2]))
            ]


def _logic_target_from_json(value: dict[str, Any]) -> LogicTarget:
    return LogicTarget(
        target_id=str(value["target_id"]),
        file=str(value["file"]),
        line_start=int(value["line_start"]),
        line_end=int(value["line_end"]),
        symbol=str(value["symbol"]),
        activated_classes=tuple(int(item) for item in value.get("activated_classes", [])),
        signals=tuple(str(item) for item in value.get("signals", [])),
        questions_for_devin=tuple(str(item) for item in value.get("questions_for_devin", [])),
        confidence=str(value.get("confidence", "MEDIUM")),
    )


def _unsupported_from_json(value: dict[str, Any]) -> UnsupportedConstruct:
    return UnsupportedConstruct(
        file=str(value["file"]),
        symbol_or_section=str(value["symbol_or_section"]),
        construct_type=str(value["construct_type"]),
        affected_categories=tuple(int(item) for item in value.get("affected_categories", [])),
        reason=str(value["reason"]),
        recommended_devin_action=str(value["recommended_devin_action"]),
        completion_impact=str(value.get("completion_impact", "PARTIAL")),
    )
