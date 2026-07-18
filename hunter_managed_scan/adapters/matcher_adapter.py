"""Expose existing matcher specifications as bounded investigation leads only."""

from __future__ import annotations

from typing import Any


def matcher_leads_for_classes(matchers: list[dict[str, Any]], class_numbers: set[int]) -> list[dict[str, Any]]:
    leads = [item for item in matchers if int(item.get("class_number", 0)) in class_numbers]
    return sorted(leads, key=lambda item: (int(item["class_number"]), str(item["matcher_family"]), str(item["matcher_id"])))
