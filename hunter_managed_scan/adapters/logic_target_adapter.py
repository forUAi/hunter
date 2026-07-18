"""Assign existing deterministic business-logic targets without deciding risk."""

from __future__ import annotations

from typing import Any


def logic_targets_for_classes(targets: list[dict[str, Any]], class_numbers: set[int]) -> list[dict[str, Any]]:
    selected = [
        target
        for target in targets
        if class_numbers.intersection(int(number) for number in target.get("activated_classes", []))
    ]
    return sorted(selected, key=lambda item: (str(item["file"]), int(item["line_start"]), str(item["target_id"])))
