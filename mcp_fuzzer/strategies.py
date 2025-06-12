from typing import Any, Dict

from hypothesis import strategies as st


def make_fuzz_strategy_from_jsonschema(schema: Dict[str, Any]):
    """Create a Hypothesis strategy for the tool's arguments based on JSON Schema."""
    props = schema.get("properties", {})
    strat_dict = {}
    for arg, prop in props.items():
        typ = prop.get("type", "string")
        if typ == "integer":
            strat_dict[arg] = st.integers()
        elif typ == "number":
            strat_dict[arg] = st.floats(allow_nan=False)
        elif typ == "string":
            strat_dict[arg] = st.text()
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
                strat_dict[arg] = st.lists(st.floats(allow_nan=False))
            elif item_type == "boolean":
                strat_dict[arg] = st.lists(st.booleans())
            else:
                strat_dict[arg] = st.lists(st.text())
        else:
            strat_dict[arg] = (
                st.none() | st.text() | st.integers() | st.floats(allow_nan=False)
            )

    return st.fixed_dictionaries(strat_dict)
