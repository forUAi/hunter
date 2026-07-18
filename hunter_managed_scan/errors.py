"""Managed-scan failures mapped to stable CLI exit codes."""

from __future__ import annotations

from . import (
    INCOMPLETE_COVERAGE,
    MISSING_VALIDATION,
    OPERATIONAL_ERROR,
    SCHEMA_OR_VERIFICATION_FAILURE,
    TARGET_REPOSITORY_MODIFIED,
)


class ManagedScanError(Exception):
    exit_code = OPERATIONAL_ERROR


class OperationalError(ManagedScanError):
    exit_code = OPERATIONAL_ERROR


class SchemaValidationError(ManagedScanError):
    exit_code = SCHEMA_OR_VERIFICATION_FAILURE


class VerificationError(ManagedScanError):
    exit_code = SCHEMA_OR_VERIFICATION_FAILURE


class IncompleteCoverageError(ManagedScanError):
    exit_code = INCOMPLETE_COVERAGE


class MissingValidationError(ManagedScanError):
    exit_code = MISSING_VALIDATION


class TargetModifiedError(ManagedScanError):
    exit_code = TARGET_REPOSITORY_MODIFIED
