import random

from mcp_fuzzer.fuzz_engine.mutators.strategies.interesting_values import (
    COMMAND_INJECTION,
    ENCODING_BYPASS,
    SQL_INJECTION,
    SSRF_PAYLOADS,
    TYPE_CONFUSION,
    XSS_PAYLOADS,
)
from mcp_fuzzer.fuzz_engine.mutators.strategies.semantic_selector import (
    SemanticPayloadSelector,
)
from mcp_fuzzer.fuzz_engine.mutators.strategies.utils import ConstraintMode


def test_tokenize_splits_camel_case_and_separators():
    tokens = SemanticPayloadSelector._tokenize("resourceURL_id")

    assert tokens == {"resource", "url", "id"}


def test_pick_string_url_uses_ssrf_payloads():
    selector = SemanticPayloadSelector(rng=random.Random(0))

    payload = selector.pick_string(
        "resource_url",
        max_length=10,
        mode=ConstraintMode.ENFORCE,
    )

    assert payload in SSRF_PAYLOADS or payload.startswith(("http", "file:"))
    assert len(payload) <= 10


def test_pick_string_command_uses_command_payloads():
    selector = SemanticPayloadSelector(rng=random.Random(1))

    payload = selector.pick_string("command", mode=ConstraintMode.ENFORCE)

    assert payload in COMMAND_INJECTION


def test_pick_string_default_falls_back_to_sql_injection():
    selector = SemanticPayloadSelector(rng=random.Random(2))

    payload = selector.pick_string("misc_field")

    assert payload in SQL_INJECTION


def test_pick_string_id_uses_unicode_trick():
    selector = SemanticPayloadSelector(rng=random.Random(3))

    payload = selector.pick_string("user_id", max_length=20)

    assert payload.startswith("tes")
    assert "t_id" in payload
    assert any(ord(ch) > 127 for ch in payload)


def test_pick_number_uses_bounds_for_min_max_tokens():
    selector = SemanticPayloadSelector(rng=random.Random(4))

    assert selector.pick_number("minValue", minimum=5, maximum=10) == 4
    assert selector.pick_number("timeout", maximum=3) == 4
    assert selector.pick_number("count") == 2147483648


def test_pick_string_path_uses_path_payload():
    selector = SemanticPayloadSelector(rng=random.Random(5))

    payload = selector.pick_string("file_path", max_length=5)

    assert len(payload) <= 5


def test_pick_string_query_uses_sql_payload():
    selector = SemanticPayloadSelector(rng=random.Random(6))

    payload = selector.pick_string("search_query", max_length=100)

    assert payload in SQL_INJECTION


def test_pick_string_html_uses_xss_payload():
    selector = SemanticPayloadSelector(rng=random.Random(7))

    payload = selector.pick_string("html_body", max_length=200)

    assert payload in XSS_PAYLOADS


def test_pick_string_encoding_uses_encoding_bypass():
    selector = SemanticPayloadSelector(rng=random.Random(8))

    payload = selector.pick_string("encoding_hint", max_length=20)

    assert payload in ENCODING_BYPASS


def test_pick_string_type_uses_type_confusion():
    selector = SemanticPayloadSelector(rng=random.Random(9))

    payload = selector.pick_string("type_cast", max_length=30)

    assert payload in TYPE_CONFUSION


def test_pick_number_defaults_to_minimum_violation():
    selector = SemanticPayloadSelector(rng=random.Random(10))

    assert selector.pick_number("value", minimum=10) == 9
