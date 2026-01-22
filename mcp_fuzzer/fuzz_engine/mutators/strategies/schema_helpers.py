"""Helpers that push schema-driven payloads toward edge cases while remaining valid."""

from __future__ import annotations

import math
import random
from datetime import datetime, timezone
from typing import Any

SQL_INJECTION = "' OR '1'='1"  # used to hint structured payload content


def apply_schema_edge_cases(
    value: Any,
    schema: dict[str, Any],
    *,
    phase: str = "aggressive",
    key: str | None = None,
) -> Any:
    """Mutate the value toward schema-valid edge cases when in aggressive phase."""
    if phase != "aggressive" or not isinstance(schema, dict):
        return value

    # Honor const/enum before type-specific branching
    if "const" in schema:
        return schema["const"]

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        schema_type = schema.get("type")
        if isinstance(schema_type, list):
            schema_type = schema_type[0]
        last_enum = enum_values[-1]
        if schema_type == "string" and not isinstance(last_enum, str):
            return str(last_enum)
        return last_enum

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = schema_type[0]

    if schema_type == "object" or schema.get("properties"):
        return _edge_object(value, schema, phase, key)
    if schema_type == "array":
        if isinstance(value, list) and value:
            return value
        return _edge_array(value, schema, phase, key)
    if schema_type == "string":
        if value is not None:
            return value
        return _edge_string(schema, key)
    if schema_type == "integer":
        if value is not None:
            return value
        return _edge_number(schema, integer=True)
    if schema_type == "number":
        if value is not None:
            return value
        return _edge_number(schema, integer=False)

    return value


def _edge_object(
    value: Any,
    schema: dict[str, Any],
    phase: str,
    key: str | None,
) -> dict[str, Any]:
    props = schema.get("properties", {})
    result: dict[str, Any] = dict(value) if isinstance(value, dict) else {}

    for prop_name, prop_schema in props.items():
        child_value = result.get(prop_name)
        if child_value is None:
            result[prop_name] = apply_schema_edge_cases(
                child_value, prop_schema, phase=phase, key=prop_name
            )

    required = schema.get("required") or []
    for prop_name in required:
        if prop_name not in result:
            result[prop_name] = apply_schema_edge_cases(
                None,
                props.get(prop_name, {}),
                phase=phase,
                key=prop_name,
            )

    additional = schema.get("additionalProperties", True)
    if additional is not False and not result:
        extra_schema = (
            additional
            if isinstance(additional, dict)
            else {"type": "string"}
        )
        for idx in range(2):
            extra_key = f"extra_field_{idx}"
            if extra_key in result:
                continue
            result[extra_key] = apply_schema_edge_cases(
                None, extra_schema, phase=phase, key=extra_key
            )

    return result


def _edge_array(
    value: Any,
    schema: dict[str, Any],
    phase: str,
    key: str | None,
) -> list[Any]:
    min_items = schema.get("minItems", 0)
    max_items = schema.get("maxItems")
    if isinstance(max_items, int):
        # Honor maxItems even when it is 0
        length = max(0, min(max_items, max(min_items, 0)))
    else:
        length = max(min_items, 3)
    if max_items is None and length < min_items:
        length = min_items

    items_schema = schema.get("items", {"type": "string"})
    if isinstance(items_schema, list):
        items = []
        for idx, item_schema in enumerate(items_schema[:length]):
            items.append(
                apply_schema_edge_cases(
                    None,
                    item_schema,
                    phase=phase,
                    key=f"{key}[{idx}]",
                )
            )
        while len(items) < length:
            items.append(
                apply_schema_edge_cases(
                    None, items_schema[-1], phase=phase, key=key
                )
            )
        return items

    lowered_key = key.lower() if key else ""
    if "focus" in lowered_key:
        focus_candidates = [
            "correctness",
            "performance",
            "security",
            "readability",
            "concurrency",
            "edge-cases",
        ]
        return (focus_candidates * math.ceil(length / len(focus_candidates)))[:length]
    if "point" in lowered_key:
        key_points = [
            "Ensure RFC compliance for new endpoints",
            "Highlight security token handling",
            "Document concurrency boundaries for tasks",
        ]
        return (key_points * math.ceil(length / len(key_points)))[:length]
    if "stack" in lowered_key or "solution" in lowered_key:
        stack_examples = [
            "Node.js + Express + WebSocket",
            "Rust + Tokio + Axum",
            "Spring Boot + Servlet",
        ]
        return (stack_examples * math.ceil(length / len(stack_examples)))[:length]

    return [
        apply_schema_edge_cases(None, items_schema, phase=phase, key=key)
        for _ in range(length)
    ]


def _edge_string(schema: dict[str, Any], key: str | None) -> str:
    """
    Generate edge case string with constraint-aware payloads.

    Uses conservative defaults instead of extreme fallbacks.
    """
    const = schema.get("const")
    if isinstance(const, str):
        return const

    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        last = enum_values[-1]
        if isinstance(last, str):
            return last
        return str(last)

    min_length = max(0, schema.get("minLength", 0))
    max_length = schema.get("maxLength")
    if isinstance(max_length, int) and max_length < min_length:
        max_length = min_length
    if isinstance(max_length, int) and max_length == 0:
        return ""
    # Conservative default: 50 instead of 64
    target_length = max_length if isinstance(max_length, int) else max(min_length, 50)
    target_length = max(target_length, min_length)
    pattern = schema.get("pattern")
    format_type = schema.get("format")

    if format_type == "date-time":
        return (
            datetime.now(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    if format_type == "uuid":
        return "f84a4f17-9f1a-4e95-a1d4-1cda0cfcf01d"
    if format_type == "email":
        # Email injection attempt
        return "fuzzer+' OR '1'='1@example.com"
    if format_type == "uri" or (key and "uri" in key.lower()):
        return _build_traversal_uri(target_length)

    if pattern == "^[0-9]+$":
        return "9" * target_length
    if pattern == "^[a-zA-Z0-9]+$":
        return "a" * target_length  # Lowercase 'a' instead of 'A'

    semantic = _semantic_string_by_key(key, min_length, target_length)
    if semantic is not None:
        return semantic

    # Constraint-aware attack payloads (fit within target_length)
    special_tokens = [
        SQL_INJECTION,
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "test\x00hidden",  # Null byte injection
        "valid-value",
    ]

    # Pick payload that fits, or use shortest
    fitting = [t for t in special_tokens if len(t) <= target_length]
    base = random.choice(fitting) if fitting else special_tokens[-1]
    return _resize_string(base, min_length, target_length)


def _build_traversal_uri(length: int) -> str:
    base = "file:///tmp/mcp-fuzzer/"
    extra = "../" * 6 + "etc/passwd"
    query = "?q=" + "A" * 40 + "%20%2F"
    candidate = (base + extra + query)[:length]
    if len(candidate) < length:
        candidate += "a" * (length - len(candidate))
    return candidate


def _resize_string(value: str, min_length: int, max_length: int) -> str:
    if len(value) < min_length:
        value = value + ("A" * (min_length - len(value)))
    if len(value) > max_length:
        value = value[:max_length]
    return value


def _edge_number(schema: dict[str, Any], integer: bool) -> int | float:
    """
    Generate edge case number with off-by-one violations.

    Uses conservative defaults (0) instead of extreme values (-2^63).
    """
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    exc_min = schema.get("exclusiveMinimum")
    exc_max = schema.get("exclusiveMaximum")

    delta = 1 if integer else 1e-3
    if isinstance(exc_min, (int, float)):
        eff_min = exc_min + delta
    elif minimum is not None:
        eff_min = minimum + delta if exc_min is True else minimum
    else:
        eff_min = None

    if isinstance(exc_max, (int, float)):
        eff_max = exc_max - delta
    elif maximum is not None:
        eff_max = maximum - delta if exc_max is True else maximum
    else:
        eff_max = None

    value: float | None = None

    # Prioritize off-by-one violations when constraints exist
    if maximum is not None:
        # Off-by-one above maximum
        value = maximum + delta
    elif minimum is not None:
        # Off-by-one below minimum
        value = minimum - delta
    elif eff_max is not None:
        value = eff_max
    elif eff_min is not None:
        value = eff_min
    else:
        # Conservative default: 0 instead of -2^63
        value = 0

    multiple_of = schema.get("multipleOf")
    if isinstance(multiple_of, (int, float)) and multiple_of != 0:
        value = math.floor(value / multiple_of) * multiple_of
        if eff_min is not None and value < eff_min:
            value = math.ceil(eff_min / multiple_of) * multiple_of
        if eff_max is not None and value > eff_max:
            value = math.floor(eff_max / multiple_of) * multiple_of

    return int(value) if integer else float(value)


def _semantic_string_by_key(
    key: str | None, min_length: int, max_length: int
) -> str | None:
    """
    Generate semantic attack payload based on field name.

    Uses constraint-aware payloads that fit within max_length.
    """
    if not key:
        return None
    lowered = key.lower()

    if "language" in lowered:
        return _resize_string("klingon-extended", min_length, max_length)
    if "file_path" in lowered or lowered.endswith("path"):
        return _build_traversal_uri(max_length)
    if any(x in lowered for x in ("query", "search", "filter", "sql")):
        return _resize_string(SQL_INJECTION, min_length, max_length)
    if any(x in lowered for x in ("html", "content", "body")):
        return _resize_string("<script>alert(1)</script>", min_length, max_length)
    if any(x in lowered for x in ("cmd", "command", "exec", "shell")):
        return _resize_string("; ls -la", min_length, max_length)
    if "analysis" in lowered:
        return _resize_string(
            "deep quantitative analysis with high precision context",
            min_length,
            max_length,
        )
    if "content_type" in lowered or "type" in lowered:
        return _resize_string("documentation-spec", min_length, max_length)
    if "audience" in lowered:
        return _resize_string("engineering-team-leads", min_length, max_length)
    if "tone" in lowered:
        return "technical"
    if "error" in lowered:
        return _resize_string(
            "Null pointer dereference in user input",
            min_length,
            max_length,
        )
    if "context" in lowered:
        return _resize_string(
            "Context: rapid external flags with nested data",
            min_length,
            max_length,
        )
    if "department" in lowered:
        return _resize_string("Compliance/Research", min_length, max_length)
    return None


def apply_semantic_combos(patched: dict[str, Any]) -> None:
    if patched.get("role") == "admin":
        try:
            age = int(patched.get("age", 13))
        except (TypeError, ValueError):
            age = 13
        patched["age"] = min(age, 17)
    operation = patched.get("operation")
    if isinstance(operation, str) and operation == "divide":
        patched["second"] = 0
