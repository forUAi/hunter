"""Small standard-library JSON Schema validator for managed artifact contracts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from hunter_managed_scan.errors import SchemaValidationError

SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    path = SCHEMA_ROOT / name
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"cannot load schema {name}") from exc
    if not isinstance(value, dict):
        raise SchemaValidationError(f"schema {name} must contain an object")
    return value


def _resolve_reference(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(f"unsupported schema reference: {reference}")
    current: Any = root
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            raise SchemaValidationError(f"invalid schema reference: {reference}")
        current = current[part]
    if not isinstance(current, dict):
        raise SchemaValidationError(f"schema reference is not an object: {reference}")
    return current


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def validate_instance(value: Any, schema: dict[str, Any], *, path: str = "$", root: dict[str, Any] | None = None) -> None:
    root = schema if root is None else root
    if "$ref" in schema:
        validate_instance(value, _resolve_reference(root, str(schema["$ref"])), path=path, root=root)
        return
    if "oneOf" in schema:
        successes = 0
        for candidate in schema["oneOf"]:
            try:
                validate_instance(value, candidate, path=path, root=root)
                successes += 1
            except SchemaValidationError:
                pass
        if successes != 1:
            raise SchemaValidationError(f"{path}: value must satisfy exactly one schema")
        return
    if "anyOf" in schema:
        for candidate in schema["anyOf"]:
            try:
                validate_instance(value, candidate, path=path, root=root)
                return
            except SchemaValidationError:
                pass
        raise SchemaValidationError(f"{path}: value does not satisfy any allowed schema")
    expected_type = schema.get("type")
    if expected_type:
        allowed = [expected_type] if isinstance(expected_type, str) else list(expected_type)
        if not any(_matches_type(value, item) for item in allowed):
            raise SchemaValidationError(f"{path}: expected {' or '.join(allowed)}")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value is not in the allowed enumeration")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise SchemaValidationError(f"{path}: missing required field(s): {', '.join(missing)}")
        properties = schema.get("properties", {})
        for key, child in value.items():
            if key in properties:
                validate_instance(child, properties[key], path=f"{path}.{key}", root=root)
            elif schema.get("additionalProperties") is False:
                raise SchemaValidationError(f"{path}: unexpected field {key}")
        if "minProperties" in schema and len(value) < int(schema["minProperties"]):
            raise SchemaValidationError(f"{path}: too few properties")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            raise SchemaValidationError(f"{path}: too few items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            raise SchemaValidationError(f"{path}: too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                raise SchemaValidationError(f"{path}: items must be unique")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                validate_instance(item, schema["items"], path=f"{path}[{index}]", root=root)
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            raise SchemaValidationError(f"{path}: string is too short")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            raise SchemaValidationError(f"{path}: string is too long")
        if "pattern" in schema and re.search(str(schema["pattern"]), value) is None:
            raise SchemaValidationError(f"{path}: string does not match required pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaValidationError(f"{path}: value is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaValidationError(f"{path}: value exceeds maximum")


def validate_artifact(value: Any, schema_name: str) -> None:
    schema = load_schema(schema_name)
    validate_instance(value, schema, root=schema)
