"""Mechanical CVSS v3.1 base-score calculation."""

from __future__ import annotations

import math

from hunter_managed_scan.errors import VerificationError

REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise VerificationError("CVSS vector must use CVSS:3.1")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise VerificationError("CVSS vector contains a malformed metric")
        key, value = part.split(":", 1)
        if key in metrics:
            raise VerificationError(f"CVSS vector repeats metric {key}")
        metrics[key] = value
    if set(metrics) != set(REQUIRED_METRICS):
        raise VerificationError("CVSS vector must contain exactly the eight base metrics")
    try:
        WEIGHTS["AV"][metrics["AV"]]
        WEIGHTS["AC"][metrics["AC"]]
        WEIGHTS["UI"][metrics["UI"]]
        for key in ("C", "I", "A"):
            WEIGHTS["CIA"][metrics[key]]
    except KeyError as exc:
        raise VerificationError(f"CVSS vector has an invalid metric value: {exc}") from exc
    if metrics["S"] not in {"U", "C"}:
        raise VerificationError("CVSS Scope must be U or C")
    if metrics["PR"] not in {"N", "L", "H"}:
        raise VerificationError("CVSS Privileges Required must be N, L, or H")
    return metrics


def _round_up(value: float) -> float:
    return math.ceil((value * 10) - 1e-10) / 10.0


def calculate_base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"
    privileges = (
        {"N": 0.85, "L": 0.68, "H": 0.5}
        if scope_changed
        else {"N": 0.85, "L": 0.62, "H": 0.27}
    )[metrics["PR"]]
    exploitability = (
        8.22
        * WEIGHTS["AV"][metrics["AV"]]
        * WEIGHTS["AC"][metrics["AC"]]
        * privileges
        * WEIGHTS["UI"][metrics["UI"]]
    )
    confidentiality = WEIGHTS["CIA"][metrics["C"]]
    integrity = WEIGHTS["CIA"][metrics["I"]]
    availability = WEIGHTS["CIA"][metrics["A"]]
    impact_subscore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
    else:
        impact = 6.42 * impact_subscore
    if impact <= 0:
        return 0.0
    combined = impact + exploitability
    return _round_up(min(1.08 * combined, 10.0) if scope_changed else min(combined, 10.0))


def severity_for_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"
