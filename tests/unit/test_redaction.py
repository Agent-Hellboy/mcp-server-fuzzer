#!/usr/bin/env python3
"""Tests for the shared redaction helpers."""

import pytest

from mcp_fuzzer.redaction import (
    REDACTED,
    is_sensitive_key,
    is_url_key,
    redact,
    redact_url,
)


class TestSensitiveKeys:
    """Key normalization: separators and case must not matter."""

    @pytest.mark.parametrize(
        "key",
        [
            "apiKey",
            "api-key",
            "API_KEY",
            "api key",
            "X-Api-Key",
            "authorization",
            "Client_Secret",
            "Cookie",
            "aws_credentials",
            "password",
            "private-key",
            "refreshToken",
            "access_token",
        ],
    )
    def test_sensitive_keys_are_detected(self, key):
        assert is_sensitive_key(key) is True
        assert redact({key: "s3cret"}) == {key: REDACTED}

    @pytest.mark.parametrize(
        "key",
        ["name", "timestamp", "success", "outcome", "args", "tool_name"],
    )
    def test_ordinary_keys_are_untouched(self, key):
        assert is_sensitive_key(key) is False
        assert redact({key: "value"}) == {key: "value"}

    def test_non_string_keys_do_not_explode(self):
        assert redact({1: "value", None: "other"}) == {1: "value", None: "other"}


class TestRedact:
    def test_nested_dicts_are_walked(self):
        payload = {
            "outer": {"inner": {"api_key": "planted", "keep": "visible"}},
        }
        assert redact(payload) == {
            "outer": {"inner": {"api_key": REDACTED, "keep": "visible"}},
        }

    def test_lists_are_walked_and_stay_lists(self):
        payload = {"runs": [{"password": "planted"}, {"ok": 1}]}
        redacted = redact(payload)
        assert isinstance(redacted["runs"], list)
        assert redacted == {"runs": [{"password": REDACTED}, {"ok": 1}]}

    def test_sensitive_key_holding_a_dict_redacts_the_whole_subtree(self):
        payload = {"credentials": {"user": "svc", "nested": {"pw": "planted"}}}
        assert redact(payload) == {"credentials": REDACTED}

    def test_sensitive_key_holding_a_list_redacts_the_whole_subtree(self):
        payload = {"tokens": [{"value": "planted"}, "planted-too"]}
        assert redact(payload) == {"tokens": REDACTED}

    def test_top_level_key_argument_redacts_scalar(self):
        assert redact("planted", "secret") == REDACTED
        assert redact("kept", "mode") == "kept"

    def test_structure_and_field_names_are_preserved(self):
        payload = {
            "tool_results": {
                "fetch_page": [{"args": {"token": "planted"}, "success": True}]
            }
        }
        redacted = redact(payload)
        assert list(redacted) == ["tool_results"]
        assert list(redacted["tool_results"]) == ["fetch_page"]
        run = redacted["tool_results"]["fetch_page"][0]
        assert list(run) == ["args", "success"]
        assert run["args"] == {"token": REDACTED}
        assert run["success"] is True

    def test_plain_redact_cannot_tell_a_container_key_from_a_secret(self):
        """Why report exports use ``redact_report_data`` instead of ``redact``.

        ``redact`` is key-driven, so a tool literally named ``get_token``
        would lose its runs. Report exports must never do that.
        """
        assert redact({"get_token": [{"success": True}]}) == {
            "get_token": REDACTED
        }

    def test_scalars_pass_through(self):
        for value in (None, 1, 1.5, True, "plain"):
            assert redact(value) is value


class TestRedactUrl:
    def test_clean_url_is_unchanged(self):
        url = "https://target.example/mcp?tool=echo&limit=5"
        assert redact_url(url) == url

    def test_userinfo_is_stripped_but_target_kept(self):
        redacted = redact_url("https://svc:hunter2@target.example:8443/mcp")
        assert redacted == "https://target.example:8443/mcp"
        assert "hunter2" not in redacted
        assert "svc" not in redacted

    def test_username_only_userinfo_is_stripped(self):
        assert redact_url("http://tok3n@target.example/mcp") == (
            "http://target.example/mcp"
        )

    def test_sensitive_query_parameter_value_is_redacted(self):
        redacted = redact_url(
            "https://target.example/mcp?access_token=eyJhbGciOi&tool=echo"
        )
        assert "eyJhbGciOi" not in redacted
        assert redacted.startswith("https://target.example/mcp?")
        assert f"access_token={REDACTED}" in redacted
        assert "tool=echo" in redacted

    def test_sensitive_fragment_parameter_is_redacted(self):
        redacted = redact_url("https://target.example/cb#access_token=eyJhbGciOi")
        assert "eyJhbGciOi" not in redacted
        assert "https://target.example/cb#" in redacted

    def test_plain_fragment_is_unchanged(self):
        url = "https://target.example/mcp#section"
        assert redact_url(url) == url

    def test_stdio_command_endpoint_is_unchanged(self):
        command = "python examples/test_server.py --flag value"
        assert redact_url(command) == command

    @pytest.mark.parametrize("value", [None, 42, "", {"a": 1}])
    def test_non_url_values_pass_through(self, value):
        assert redact_url(value) == value

    def test_unparseable_url_still_loses_userinfo(self):
        # An invalid IPv6 literal makes urlsplit raise; the fallback still runs.
        redacted = redact_url("https://svc:hunter2@[bad/mcp")
        assert "hunter2" not in redacted


class TestUrlKeys:
    @pytest.mark.parametrize(
        "key", ["endpoint", "url", "server_url", "base-uri", "targetURL"]
    )
    def test_url_keys_are_detected(self, key):
        assert is_url_key(key) is True

    @pytest.mark.parametrize("key", ["security", "mode", "name", "curl_command"])
    def test_other_keys_are_not_url_keys(self, key):
        assert is_url_key(key) is False

    def test_url_values_lose_credentials_but_keep_the_target(self):
        payload = {"evidence": {"endpoint": "http://svc:hunter2@target/mcp"}}
        assert redact(payload) == {"evidence": {"endpoint": "http://target/mcp"}}

    def test_non_url_string_under_url_key_is_unchanged(self):
        assert redact({"endpoint": "stdio"}) == {"endpoint": "stdio"}
