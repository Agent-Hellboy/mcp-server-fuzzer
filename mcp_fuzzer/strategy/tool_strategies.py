#!/usr/bin/env python3
"""
Tool Fuzzing Strategies

This module contains Hypothesis strategies for generating fuzz data
for MCP tool arguments.
"""

import random
import string
from typing import Any, Dict

from hypothesis import strategies as st

# Special characters and edge cases for aggressive fuzzing
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\"
UNICODE_CHARS = "🚀🔥💯🎯⚡🌟💎🎪🎭🎨🎬🎤🎧🎼🎹🎸🎻🎺🎷🥁"
NULL_BYTES = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
ESCAPE_CHARS = "\\n\\t\\r\\b\\f\\v\\a"
HTML_ENTITIES = "&lt;&gt;&amp;&quot;&apos;&nbsp;&copy;&reg;&trade;"
SQL_INJECTION = [
    "' OR 1=1; --",
    "'; DROP TABLE users; --",
    "1' UNION SELECT * FROM users --",
]
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
]
PATH_TRAVERSAL = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"]
OVERFLOW_VALUES = ["A" * 10000, "0" * 10000, "💯" * 1000, "🚀" * 1000]


class ToolStrategies:
    """Hypothesis strategies for tool argument fuzzing."""

    @staticmethod
    def _generate_aggressive_text(min_size: int = 1, max_size: int = 100) -> str:
        """Generate aggressive random text with extensive edge cases."""
        length = random.randint(min_size, max_size)

        # Choose from various text generation strategies
        strategy = random.choice(
            [
                "normal",
                "special_chars",
                "unicode",
                "null_bytes",
                "escape_chars",
                "html_entities",
                "sql_injection",
                "xss",
                "path_traversal",
                "overflow",
                "mixed",
                "extreme",
            ]
        )

        if strategy == "normal":
            chars = string.ascii_letters + string.digits
            return "".join(random.choice(chars) for _ in range(length))
        elif strategy == "special_chars":
            return "".join(random.choice(SPECIAL_CHARS) for _ in range(length))
        elif strategy == "unicode":
            return "".join(random.choice(UNICODE_CHARS) for _ in range(length))
        elif strategy == "null_bytes":
            return "".join(random.choice(NULL_BYTES) for _ in range(length))
        elif strategy == "escape_chars":
            return "".join(random.choice(ESCAPE_CHARS) for _ in range(length))
        elif strategy == "html_entities":
            return "".join(random.choice(HTML_ENTITIES) for _ in range(length))
        elif strategy == "sql_injection":
            return random.choice(SQL_INJECTION)
        elif strategy == "xss":
            return random.choice(XSS_PAYLOADS)
        elif strategy == "path_traversal":
            return random.choice(PATH_TRAVERSAL)
        elif strategy == "overflow":
            return random.choice(OVERFLOW_VALUES)
        elif strategy == "mixed":
            chars = string.printable + UNICODE_CHARS + SPECIAL_CHARS
            return "".join(random.choice(chars) for _ in range(length))
        elif strategy == "extreme":
            extreme_values = [
                "",  # Empty string
                " " * length,  # Spaces only
                "\t" * length,  # Tabs only
                "\n" * length,  # Newlines only
                "0" * length,  # Zeros only
                "A" * length,  # A's only
                "💯" * (length // 2),  # Unicode only
                "!@#" * (length // 3),  # Special chars only
            ]
            return random.choice(extreme_values)
        else:
            return "".join(random.choice(string.printable) for _ in range(length))

    @staticmethod
    def _generate_aggressive_integer(
        min_value: int = -1000000, max_value: int = 1000000
    ) -> int:
        """Generate aggressive random integer with extreme values and edge cases."""
        strategy = random.choice(
            ["normal", "extreme", "zero", "negative", "overflow", "special", "boundary"]
        )

        if strategy == "normal":
            return random.randint(min_value, max_value)
        elif strategy == "extreme":
            extreme_values = [
                -2147483648,
                2147483647,
                -9223372036854775808,
                9223372036854775807,
                0,
                1,
                -1,
            ]
            return random.choice(extreme_values)
        elif strategy == "zero":
            return 0
        elif strategy == "negative":
            return random.randint(-1000000, -1)
        elif strategy == "overflow":
            overflow_values = [2**31, 2**63, -(2**31), -(2**63), 2**64, -(2**64)]
            return random.choice(overflow_values)
        elif strategy == "special":
            # Sometimes return None for fuzzing, but keep it as integer when
            # returning a value
            if random.random() < 0.1:
                return None
            return random.randint(min_value, max_value)
        elif strategy == "boundary":
            boundary_values = [min_value, max_value, min_value + 1, max_value - 1]
            return random.choice(boundary_values)
        else:
            return random.randint(min_value, max_value)

    @staticmethod
    def _generate_aggressive_float(
        min_value: float = -1000000.0, max_value: float = 1000000.0
    ) -> float:
        """Generate aggressive random float with extreme values and edge cases."""
        strategy = random.choice(
            [
                "normal",
                "extreme",
                "zero",
                "negative",
                "infinity",
                "nan",
                "special",
                "precision",
            ]
        )

        if strategy == "normal":
            return random.uniform(min_value, max_value)
        elif strategy == "extreme":
            extreme_values = [
                float("inf"),
                float("-inf"),
                1e308,
                -1e308,
                1e-308,
                -1e-308,
            ]
            return random.choice(extreme_values)
        elif strategy == "zero":
            return 0.0
        elif strategy == "negative":
            return random.uniform(-1000000.0, -0.1)
        elif strategy == "infinity":
            return random.choice([float("inf"), float("-inf")])
        elif strategy == "nan":
            return float("nan")
        elif strategy == "special":
            if random.random() < 0.1:
                return random.choice([None, "not_a_number", "infinity"])
            return random.uniform(min_value, max_value)
        elif strategy == "precision":
            # Generate very precise or very imprecise numbers
            if random.random() < 0.5:
                return round(
                    random.uniform(min_value, max_value), random.randint(0, 15)
                )
            else:
                return random.uniform(min_value, max_value)
        else:
            return random.uniform(min_value, max_value)

    @staticmethod
    def _generate_aggressive_boolean() -> Any:
        """Generate aggressive random boolean with edge cases."""
        if random.random() < 0.2:  # 20% chance for edge cases
            return random.choice(
                [None, True, False, "", "yes", "no", "Y", "N", "y", "n"]
            )
        return random.choice([True, False])

    @staticmethod
    def _generate_aggressive_object() -> Dict[str, Any]:
        """Generate aggressive random object with edge cases."""
        strategy = random.choice(
            [
                "normal",
                "empty",
                "large",
                "nested",
                "special_keys",
                "special_values",
                "mixed",
            ]
        )

        if strategy == "normal":
            num_keys = random.randint(1, 10)
            obj = {}
            for _ in range(num_keys):
                key = ToolStrategies._generate_aggressive_text(1, 20)
                value = ToolStrategies._generate_aggressive_text(1, 50)
                obj[key] = value
            return obj
        elif strategy == "empty":
            return {}
        elif strategy == "large":
            num_keys = random.randint(50, 500)
            obj = {}
            for _ in range(num_keys):
                key = ToolStrategies._generate_aggressive_text(1, 30)
                value = ToolStrategies._generate_aggressive_text(1, 200)
                obj[key] = value
            return obj
        elif strategy == "nested":
            return {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": ToolStrategies._generate_aggressive_text(1, 50)
                        }
                    }
                }
            }
        elif strategy == "special_keys":
            return {
                "": ToolStrategies._generate_aggressive_text(),
                "null": None,
                "special!@#": ToolStrategies._generate_aggressive_text(),
                "unicode🚀": ToolStrategies._generate_aggressive_text(),
                "very_long_key_"
                + "a" * 200: ToolStrategies._generate_aggressive_text(),
                "key_with_spaces ": ToolStrategies._generate_aggressive_text(),
                "key\twith\ttabs": ToolStrategies._generate_aggressive_text(),
                "key\nwith\nnewlines": ToolStrategies._generate_aggressive_text(),
            }
        elif strategy == "special_values":
            return {
                "null_value": None,
                "empty_string": "",
                "zero": 0,
                "false": False,
                "empty_list": [],
                "empty_object": {},
                "special_chars": "!@#$%^&*()",
                "unicode": "🚀🔥💯",
                "sql_injection": random.choice(SQL_INJECTION),
                "xss": random.choice(XSS_PAYLOADS),
                "path_traversal": random.choice(PATH_TRAVERSAL),
                "overflow": random.choice(OVERFLOW_VALUES),
                "very_long_value": "A" * 10000,
                "mixed_content": "🚀🔥💯!@#$%^&*()1234567890",
            }
        elif strategy == "mixed":
            obj = {}
            for _ in range(random.randint(5, 15)):
                key = ToolStrategies._generate_aggressive_text(1, 15)
                value_type = random.choice(
                    ["text", "integer", "float", "boolean", "object", "list"]
                )
                if value_type == "text":
                    obj[key] = ToolStrategies._generate_aggressive_text(1, 100)
                elif value_type == "integer":
                    obj[key] = ToolStrategies._generate_aggressive_integer()
                elif value_type == "float":
                    obj[key] = ToolStrategies._generate_aggressive_float()
                elif value_type == "boolean":
                    obj[key] = ToolStrategies._generate_aggressive_boolean()
                elif value_type == "object":
                    obj[key] = ToolStrategies._generate_aggressive_object()
                elif value_type == "list":
                    obj[key] = ToolStrategies._generate_aggressive_list()
            return obj
        else:
            return {"default": ToolStrategies._generate_aggressive_text()}

    @staticmethod
    def _generate_aggressive_list() -> list:
        """Generate aggressive random list with edge cases."""
        strategy = random.choice(
            ["normal", "empty", "large", "mixed", "nested", "special", "extreme"]
        )

        if strategy == "normal":
            length = random.randint(1, 20)
            return [
                ToolStrategies._generate_aggressive_text(1, 50) for _ in range(length)
            ]
        elif strategy == "empty":
            return []
        elif strategy == "large":
            length = random.randint(100, 1000)
            return [
                ToolStrategies._generate_aggressive_text(1, 100) for _ in range(length)
            ]
        elif strategy == "mixed":
            length = random.randint(5, 25)
            result = []
            for _ in range(length):
                value_type = random.choice(
                    ["text", "integer", "float", "boolean", "object", "list", "null"]
                )
                if value_type == "text":
                    result.append(ToolStrategies._generate_aggressive_text(1, 50))
                elif value_type == "integer":
                    result.append(ToolStrategies._generate_aggressive_integer())
                elif value_type == "float":
                    result.append(ToolStrategies._generate_aggressive_float())
                elif value_type == "boolean":
                    result.append(ToolStrategies._generate_aggressive_boolean())
                elif value_type == "object":
                    result.append(ToolStrategies._generate_aggressive_object())
                elif value_type == "list":
                    result.append(ToolStrategies._generate_aggressive_list())
                elif value_type == "null":
                    result.append(None)
            return result
        elif strategy == "nested":
            length = random.randint(3, 10)
            return [
                [
                    ToolStrategies._generate_aggressive_text(1, 20)
                    for _ in range(random.randint(1, 5))
                ]
                for _ in range(length)
            ]
        elif strategy == "special":
            return [None, "", 0, False, [], {}, "special_value", "🚀🔥💯", "!@#$%^&*()"]
        elif strategy == "extreme":
            extreme_values = [
                [],  # Empty list
                [None] * 100,  # List of None values
                [""] * 100,  # List of empty strings
                ["A" * 1000] * 10,  # List of very long strings
                [
                    ToolStrategies._generate_aggressive_text(1, 1000) for _ in range(50)
                ],  # Large mixed list
            ]
            return random.choice(extreme_values)
        else:
            length = random.randint(1, 10)
            return [
                ToolStrategies._generate_aggressive_text(1, 50) for _ in range(length)
            ]

    @staticmethod
    def make_fuzz_strategy_from_jsonschema(schema: Dict[str, Any]):
        """Create a Hypothesis strategy based on JSON Schema."""
        props = schema.get("properties", {})
        strat_dict = {}

        for arg, prop in props.items():
            typ = prop.get("type", "string")

            if typ == "integer":
                strat_dict[arg] = st.integers(min_value=-1000000, max_value=1000000)
            elif typ == "number":
                strat_dict[arg] = st.floats(allow_nan=True, allow_infinity=True)
            elif typ == "string":
                strat_dict[arg] = st.text(min_size=1, max_size=1000)
            elif typ == "boolean":
                strat_dict[arg] = st.booleans()
            elif typ == "object":
                strat_dict[arg] = st.dictionaries(st.text(), st.text())
            elif typ == "array":
                items = prop.get("items", {"type": "string"})
                item_type = items.get("type", "string")

                if item_type == "integer":
                    strat_dict[arg] = st.lists(st.integers())
                elif item_type == "number":
                    strat_dict[arg] = st.lists(st.floats(allow_nan=True))
                elif item_type == "boolean":
                    strat_dict[arg] = st.lists(st.booleans())
                elif item_type == "array":
                    strat_dict[arg] = st.lists(st.lists(st.text()))
                else:
                    strat_dict[arg] = st.lists(st.text())
            else:
                strat_dict[arg] = (
                    st.none() | st.text() | st.integers() | st.floats(allow_nan=True)
                )

        return st.fixed_dictionaries(strat_dict)

    @staticmethod
    def _generate_random_value_for_type(typ: str, prop: Dict[str, Any] = None) -> Any:
        """Generate a random value for a given type with aggressive fuzzing."""
        if typ == "integer":
            return ToolStrategies._generate_aggressive_integer()
        elif typ == "number":
            return ToolStrategies._generate_aggressive_float()
        elif typ == "string":
            return ToolStrategies._generate_aggressive_text(1, 200)
        elif typ == "boolean":
            return ToolStrategies._generate_aggressive_boolean()
        elif typ == "object":
            return ToolStrategies._generate_aggressive_object()
        elif typ == "array":
            items = (
                prop.get("items", {"type": "string"}) if prop else {"type": "string"}
            )
            item_type = items.get("type", "string")
            array_length = random.randint(1, 20)
            return [
                ToolStrategies._generate_random_value_for_type(item_type, items)
                for _ in range(array_length)
            ]
        else:
            # Default to aggressive text for unknown types
            return ToolStrategies._generate_aggressive_text(1, 100)

    @staticmethod
    def fuzz_tool_arguments(tool: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fuzz arguments for a tool based on its schema."""
        schema = tool.get("inputSchema", {})
        props = schema.get("properties", {})
        result = {}

        for arg, prop in props.items():
            typ = prop.get("type", "string")
            result[arg] = ToolStrategies._generate_random_value_for_type(typ, prop)

        return result
