"""Testable boundary for parent-managed child sessions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SessionStatus:
    session_id: str
    state: str
    actual_acu: float | None = None
    result_branch: str | None = None


class SessionGateway(Protocol):
    """Implemented by the deployment environment, never by the scan core."""

    def create(self, *, role: str, task_id: str, prompt: str, maximum_acu: int) -> str: ...

    def status(self, session_id: str) -> SessionStatus: ...

    def usage(self, session_id: str) -> float | None: ...
