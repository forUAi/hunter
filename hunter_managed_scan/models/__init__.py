"""Typed artifact models for the managed Hunter workflow."""

from .coverage import CoverageEntry, CoveragePlan
from .critic import CriticDecision, CriticResult
from .final_output import FinalOutput
from .finding import AffectedInstance, Finding
from .manifest import BudgetConfiguration, RunManifest, TargetSnapshot
from .validation import ValidationPack, ValidationResult
from .work_package import WorkPackage

__all__ = [
    "AffectedInstance",
    "BudgetConfiguration",
    "CoverageEntry",
    "CoveragePlan",
    "CriticDecision",
    "CriticResult",
    "FinalOutput",
    "Finding",
    "RunManifest",
    "TargetSnapshot",
    "ValidationPack",
    "ValidationResult",
    "WorkPackage",
]
