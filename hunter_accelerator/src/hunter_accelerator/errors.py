"""Fail-closed accelerator errors."""


class AcceleratorError(Exception):
    """Base class for trusted, user-displayable accelerator failures."""


class ConfigurationError(AcceleratorError):
    """Invalid CLI or filesystem configuration."""


class TaxonomyValidationError(AcceleratorError):
    """The machine-readable Hunter All contract is inconsistent."""


class WorkspaceSafetyError(AcceleratorError):
    """A requested filesystem operation would violate read-only isolation."""


class OutputValidationError(AcceleratorError):
    """Generated artifacts failed deterministic validation."""
