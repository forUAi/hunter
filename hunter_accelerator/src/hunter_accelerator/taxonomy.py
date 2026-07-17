"""Startup validation for the exact machine-readable Hunter All taxonomy."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import TaxonomyValidationError
from .models import TaxonomyBundle

EXPECTED_ALWAYS = frozenset({10, 11, 22, 25, 38, 43, 46, 49, 50, 55, 56, 57})
EXPECTED_ABSENCE = frozenset({10, 18, 20, 27, 32, 35, 40, 48, 59, 60, 62, 84})
EXPECTED_LOGIC = frozenset({10, 11, 49, 50, 55, 56})
EXPECTED_BUILDERS = frozenset(
    {
        "rhel-tomcat", "rhel-nginx", "rhel-python", "rhel-nodejs", "rhel-jdk", "rhel-jboss", "rhel-go",
        "rhel-dotnet", "rhel-ruby", "alpine-jdk", "alpine-nodejs", "alpine-python", "alpine-dotnet",
        "alpine-builder", "ubi8-builder", "ubi9-builder",
    }
)
EXPECTED_NAMES = (
    "SQL Injection", "Command Injection", "LDAP/Expression Injection", "SSTI", "XXE",
    "HTTP Header Injection/Response Splitting", "Email Header Injection", "XSS", "HTTP Parameter Pollution",
    "AUTHZ", "IDOR", "Privilege Escalation", "SSRF", "Business-Level Authorization", "Open Redirect",
    "API Security", "Path Traversal", "CSRF", "GraphQL", "Clickjacking", "Cryptographic Failures",
    "Secrets in Code", "File Upload", "Git History Secrets", "CBOM + PQC", "HSM/Hardware key handling",
    "Authentication Bypass", "Session Management", "JWT", "OAuth/OIDC", "HTTP Request Smuggling",
    "WebSocket Security", "Sensitive Data Exposure", "Sensitive Data in Logs", "Insufficient Logging",
    "Log Injection/Forging", "Privacy/Data Protection", "Security Misconfiguration", "CORS Misconfiguration",
    "CSP Misconfiguration", "Web Cache Poisoning", "Subdomain Takeover", "Vulnerable Dependencies/SCA",
    "CI/CD Pipeline Injection", "License Compliance", "Dead Code/Unused Deps", "Insecure Deserialization",
    "Missing Rate Limiting", "Business Field Validation", "Race/Idempotency", "Concurrency on Shared Mutable State",
    "Cross-Component Correctness", "ReDoS", "Prototype Pollution", "Audit Integrity", "Data Consistency",
    "Mishandling of Exceptional Conditions", "Chained Attack Surfaces", "Container/Dockerfile Security",
    "IaC Security", "Cloud Configuration Security", "CSPM", "Hydra Buildpack Security",
    "Mobile Application Security (MAST)", "Binary-Level Mobile", "LLM01 Prompt Injection",
    "LLM02 Sensitive Information Disclosure", "LLM03 LLM Supply Chain", "LLM04 Data & Model Poisoning",
    "LLM05 Improper Output Handling", "LLM06 Excessive Agency", "LLM07 System Prompt Leakage",
    "LLM08 Vector & Embedding Weaknesses", "LLM09 Misinformation", "LLM10 Unbounded Consumption",
    "ASI01 Agent Goal Hijack", "ASI02 Tool Misuse", "ASI03 Identity & Privilege Abuse",
    "ASI04 Unexpected Code Execution", "ASI05 Insecure Inter-Agent Communication", "ASI06 Agentic Supply Chain",
    "ASI07 Memory & Context Poisoning", "ASI08 Cascading Failures", "ASI09 Human-Agent Trust Exploitation",
    "ASI10 Rogue Agents",
)


def _expected_owasp(number: int) -> str:
    if 1 <= number <= 9:
        return "A05"
    if 10 <= number <= 20:
        return "A01"
    if 21 <= number <= 26:
        return "A04"
    if 27 <= number <= 32:
        return "A07"
    if 33 <= number <= 37:
        return "A09"
    if 38 <= number <= 42 or 59 <= number <= 65:
        return "A02"
    if 43 <= number <= 46:
        return "A03"
    if number in {47, 55, 56}:
        return "A08"
    if 48 <= number <= 54:
        return "A06"
    if number == 57:
        return "A10"
    if number == 58:
        return "CHAIN"
    if 66 <= number <= 75:
        return f"LLM{number - 65:02d}"
    return f"ASI{number - 75:02d}"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            result = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise TaxonomyValidationError(f"cannot read taxonomy data: {path.name}") from exc
    if not isinstance(result, dict):
        raise TaxonomyValidationError(f"taxonomy file must contain an object: {path.name}")
    return result


def _number_set(path: Path) -> frozenset[int]:
    data = _read_json(path)
    values = data.get("class_numbers")
    if not isinstance(values, list) or not all(isinstance(value, int) for value in values):
        raise TaxonomyValidationError(f"invalid class number list: {path.name}")
    return frozenset(values)


def load_and_validate_taxonomy(taxonomy_path: Path) -> TaxonomyBundle:
    source_path = taxonomy_path.expanduser().resolve(strict=True)
    base = source_path.parent
    data = _read_json(source_path)
    classes = data.get("classes")
    if not isinstance(classes, list) or len(classes) != 85:
        raise TaxonomyValidationError("taxonomy must contain exactly 85 classes")
    required = {
        "class_number", "class_name", "owasp", "family", "always_applicable", "absence_class", "logic_class",
        "carriers", "target_file_globs", "signal_descriptions", "negative_evidence_searches", "mandatory_matcher_families",
    }
    numbers: list[int] = []
    for item in classes:
        if not isinstance(item, dict) or not required.issubset(item):
            raise TaxonomyValidationError("each taxonomy class must contain every required field")
        number = item["class_number"]
        if not isinstance(number, int):
            raise TaxonomyValidationError("class_number must be an integer")
        numbers.append(number)
        if not 1 <= number <= 85:
            raise TaxonomyValidationError("class_number must be between 1 and 85")
        if item["class_name"] != EXPECTED_NAMES[number - 1]:
            raise TaxonomyValidationError(f"class {number} name does not match Hunter All")
        owasp = item["owasp"]
        valid_owasp = bool(re.fullmatch(r"A(?:0[1-9]|10)|LLM(?:0[1-9]|10)|ASI(?:0[1-9]|10)", str(owasp)))
        if number == 58 and owasp == "CHAIN":
            valid_owasp = True
        if not valid_owasp:
            raise TaxonomyValidationError(f"class {number} has invalid OWASP mapping")
        if owasp != _expected_owasp(number):
            raise TaxonomyValidationError(f"class {number} OWASP mapping does not match Hunter All")
        if not all(isinstance(item[field], bool) for field in ("always_applicable", "absence_class", "logic_class")):
            raise TaxonomyValidationError(f"class {number} applicability flags must be booleans")
        for field_name in ("carriers", "target_file_globs", "signal_descriptions", "negative_evidence_searches", "mandatory_matcher_families"):
            if not isinstance(item[field_name], list):
                raise TaxonomyValidationError(f"class {number} has invalid {field_name}")
        if not item["carriers"] or not item["signal_descriptions"] or not item["negative_evidence_searches"]:
            raise TaxonomyValidationError(f"class {number} lacks required carrier or evidence specifications")
        if not item["mandatory_matcher_families"]:
            raise TaxonomyValidationError(f"class {number} lacks a mandatory matcher family or handoff")
    if sorted(numbers) != list(range(1, 86)) or len(set(numbers)) != 85:
        raise TaxonomyValidationError("class numbers must be unique and contiguous from 1 through 85")
    always = _number_set(base / "always_applicable.json")
    absence = _number_set(base / "absence_classes.json")
    logic = _number_set(base / "logic_classes.json")
    declared_always = frozenset(item["class_number"] for item in classes if item["always_applicable"])
    declared_absence = frozenset(item["class_number"] for item in classes if item["absence_class"])
    declared_logic = frozenset(item["class_number"] for item in classes if item["logic_class"])
    if always != EXPECTED_ALWAYS or declared_always != EXPECTED_ALWAYS:
        raise TaxonomyValidationError("always-applicable classes do not match Hunter All")
    if absence != EXPECTED_ABSENCE or declared_absence != EXPECTED_ABSENCE:
        raise TaxonomyValidationError("absence-detection classes do not match Hunter All")
    if logic != EXPECTED_LOGIC or declared_logic != EXPECTED_LOGIC:
        raise TaxonomyValidationError("standing logic classes do not match Hunter All")
    carrier_rules = _read_json(base / "carrier_rules.json")
    applicability_rules = _read_json(base / "applicability_rules.json")
    llm = carrier_rules.get("llm_agentic", {})
    content_globs = set(llm.get("content_globs", []))
    required_content = {"**/SKILL.md", "**/*.prompt", "**/.cursorrules", "**/*mcp*.json", "**/*tool*.json"}
    if set(llm.get("classes", [])) != set(range(66, 86)) or not required_content.issubset(content_globs):
        raise TaxonomyValidationError("LLM and Agentic rules must include every content carrier")
    for item in classes[65:85]:
        if not ({"prompt or instruction", "LLM SDK", "agent tool", "MCP", "agent memory", "vector database"} & set(item["carriers"])):
            raise TaxonomyValidationError(f"AI class {item['class_number']} lacks an AI/content carrier")
    hydra = carrier_rules.get("hydra", {})
    if frozenset(hydra.get("approved_builders", [])) != EXPECTED_BUILDERS:
        raise TaxonomyValidationError("Hydra approved builder registry must contain the supplied 16 builders")
    if hydra.get("approved_registry") != "artifactory.aexp.com/paas-registry/buildpacks/":
        raise TaxonomyValidationError("Hydra approved registry is invalid")
    eol = hydra.get("eol", {})
    if set(eol.get("java", {}).get("flag", [])) != {"8", "11"} or set(eol.get("node", {}).get("flag", [])) != {"16", "18"}:
        raise TaxonomyValidationError("Hydra EOL overrides are incomplete")
    hydra_check_ids = [entry.get("id") for entry in hydra.get("checks", []) if isinstance(entry, dict)]
    if hydra_check_ids != list(range(22, 28)):
        raise TaxonomyValidationError("Hydra checks 22 through 27 must be represented")
    if hydra.get("workflow_presence_is_carrier") is not True:
        raise TaxonomyValidationError("Hydra CI workflow carrier rule is missing")
    container = carrier_rules.get("container", {})
    container_check_ids = [entry.get("id") for entry in container.get("checks", []) if isinstance(entry, dict)]
    carrier_ids = [entry.get("id") for entry in container.get("carriers", []) if isinstance(entry, dict)]
    if container_check_ids != list(range(1, 22)) or carrier_ids != list("abcdefghi"):
        raise TaxonomyValidationError("container carriers a-i and hardening checks 1-21 must be represented")
    mobile = carrier_rules.get("mobile", {})
    mast_ids = [entry.get("id") for entry in mobile.get("mast", []) if isinstance(entry, dict)]
    if mobile.get("classes") != [64, 65] or mast_ids != [f"M{number}" for number in range(1, 11)]:
        raise TaxonomyValidationError("mobile carriers and M1-M10 coverage are incomplete")
    if "**/*.aab" not in mobile.get("carrier_globs", []):
        raise TaxonomyValidationError("binary mobile AAB coverage is missing")
    pqc = carrier_rules.get("pqc", {})
    if pqc.get("class_number") != 25 or set(pqc.get("tags", {})) != {
        "pqc_vulnerable", "pqc_weakened", "pqc_safe", "pqc_hybrid"
    }:
        raise TaxonomyValidationError("Class 25 PQC preparation rules are incomplete")
    return TaxonomyBundle(
        source_path=source_path,
        version=str(data.get("taxonomy_version", "")),
        profile_id=str(data.get("profile_id", "")),
        classes=tuple(classes),
        always_applicable=always,
        absence_classes=absence,
        logic_classes=logic,
        carrier_rules=carrier_rules,
        applicability_rules=applicability_rules,
    )
