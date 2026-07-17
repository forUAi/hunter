"""Explicit unsupported-construct discovery for fail-closed Phase 1 completion."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .models import FileRecord, UnsupportedConstruct

PATTERNS: tuple[tuple[str, re.Pattern[str], tuple[int, ...], str], ...] = tuple(
    (kind, re.compile(pattern, re.IGNORECASE | re.MULTILINE), categories, action)
    for kind, pattern, categories, action in (
        ("dynamic reflection", r"Class\.forName\s*\([^\"']|getDeclaredMethod\s*\([^\"']|Assembly\.Load\s*\([^\"']|importlib\.import_module\s*\([^\"']", (10, 11, 27, 47, 57), "Inspect dynamically selected types and call targets with the original Hunter All process."),
        ("generated route", r"\b(registerRoutes|addRoutes|mountRoutes|registerHandlers)\s*\([^\n]{0,120}(config|routes|handlers)", (10, 11, 14, 18, 27, 35, 48), "Enumerate generated endpoints and controls manually."),
        ("runtime-created query", r"(query|sql)\s*=\s*(eval|compile)\s*\(|createQuery\s*\(\s*[A-Za-z_]\w*\s*\)", (1, 11, 33, 49, 56), "Trace the runtime query builder and all inputs manually."),
        ("encrypted configuration", r"\b(ENC|encrypted|ciphertext)\s*\([^\n]{8,}|^\s*(sops|age):\s*$", (22, 25, 26, 27, 38, 61, 62), "Resolve the configuration through an authorized, non-secret-leaking process."),
        ("custom build DSL", r"\b(customBuild|internalBuild|companyBuild)\s*\(", (43, 44, 45, 46, 59, 63), "Inspect the custom build DSL and generated commands manually."),
        ("unusual ORM", r"\b(customOrm|internalRepository|dynamicRepository)\s*(?:\.|\()", (1, 11, 16, 33, 49, 56), "Identify the ORM query and binding semantics manually."),
        ("internal authentication wrapper", r"\b(internalAuth|customAuth|companyAuth)\s*(?:\.|\()", (10, 11, 12, 14, 27, 28, 35), "Trace the internal authentication and authorization wrapper manually."),
    )
)


def detect_unsupported(record: FileRecord, text: str | None) -> tuple[UnsupportedConstruct, ...]:
    results: list[UnsupportedConstruct] = []
    if record.binary and record.mobile:
        results.append(
            UnsupportedConstruct(
                file=record.relative_path,
                symbol_or_section="<binary>",
                construct_type="binary mobile artifact",
                affected_categories=(65,),
                reason="Phase 1 inventories but does not decompile APK/IPA/AAB binaries.",
                recommended_devin_action="Perform the original Hunter All binary-mobile investigation for this artifact.",
            )
        )
    if text is None:
        return tuple(results)
    if record.encoding_errors:
        results.append(
            UnsupportedConstruct(
                file=record.relative_path,
                symbol_or_section="<file>",
                construct_type="invalid text encoding",
                affected_categories=tuple(range(1, 86)) if record.security_relevant else (),
                reason=f"UTF-8 decoding replaced {record.encoding_errors} invalid sequence(s).",
                recommended_devin_action="Read this file with its declared encoding and repeat relevant Hunter All searches.",
            )
        )
    path = PurePosixPath(record.relative_path)
    is_helm_template = bool({"helm", "charts"} & {part.lower() for part in path.parts}) or path.name.lower() in {
        "chart.yaml",
        "kustomization.yaml",
    }
    if is_helm_template and "{{" in text and "}}" in text:
        results.append(
            UnsupportedConstruct(
                file=record.relative_path,
                symbol_or_section="<template>",
                construct_type="unresolved Helm or infrastructure template",
                affected_categories=(22, 38, 59, 60, 61, 62, 63),
                reason="Template expansion can change security-relevant values and resources.",
                recommended_devin_action="Inspect rendered variants or run the original Hunter All carrier review manually.",
            )
        )
    for construct_type, pattern, affected, action in PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        line = text.count("\n", 0, match.start()) + 1
        results.append(
            UnsupportedConstruct(
                file=record.relative_path,
                symbol_or_section=f"line {line}",
                construct_type=construct_type,
                affected_categories=affected,
                reason="The relevant target or security semantics are selected dynamically or use an unsupported abstraction.",
                recommended_devin_action=action,
            )
        )
    return tuple(results)
