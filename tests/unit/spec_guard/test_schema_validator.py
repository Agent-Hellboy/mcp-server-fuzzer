#!/usr/bin/env python3
"""
Unit tests for schema validator helpers.
"""

from types import SimpleNamespace

from mcp_fuzzer.spec_guard import schema_validator as sv


def test_validate_definition_no_jsonschema(monkeypatch):
    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", False)

    checks = sv.validate_definition("Tool", {"name": "example"})

    assert checks[0]["status"] == "WARN"
    assert "jsonschema not installed" in checks[0]["message"]


def test_validate_definition_schema_load_failure(monkeypatch):
    def _raise_load_error(version):
        raise RuntimeError("boom")

    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(sv, "_load_schema", _raise_load_error)

    checks = sv.validate_definition("Tool", {"name": "example"})

    assert checks[0]["status"] == "WARN"
    assert "Schema load failed" in checks[0]["message"]


def test_validate_definition_missing_definition(monkeypatch):
    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(sv, "_load_schema", lambda version: {"definitions": {}})

    checks = sv.validate_definition("Tool", {"name": "example"})

    assert checks[0]["status"] == "WARN"
    assert "Schema definition not found" in checks[0]["message"]


def test_validate_definition_uses_defs(monkeypatch):
    def _validator_for(schema, default=None):
        class Validator:
            def __init__(self, wrapper):
                self.wrapper = wrapper

            def iter_errors(self, instance):
                return []

        return Validator

    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(
        sv,
        "_load_schema",
        lambda version: {"$schema": "x", "$defs": {"Thing": {}}},
    )
    monkeypatch.setattr(sv, "Draft202012Validator", object())
    monkeypatch.setattr(
        sv,
        "validators",
        SimpleNamespace(validator_for=_validator_for),
    )

    checks = sv.validate_definition("Thing", {"name": "example"})

    assert checks[0]["status"] == "PASS"


def test_validate_definition_validator_error(monkeypatch):
    def _raise_validator_error(schema, default=None):
        raise ValueError("bad")

    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(
        sv,
        "_load_schema",
        lambda version: {"$schema": "x", "definitions": {"Thing": {}}},
    )
    monkeypatch.setattr(sv, "Draft202012Validator", object())
    monkeypatch.setattr(
        sv,
        "validators",
        SimpleNamespace(validator_for=_raise_validator_error),
    )

    checks = sv.validate_definition("Thing", {"name": "example"})

    assert checks[0]["status"] == "WARN"
    assert "Schema dialect not recognized" in checks[0]["message"]


def test_validate_definition_failure_checks(monkeypatch):
    class FakeError:
        def __init__(self, message):
            self.message = message
            self.path = ()

    def _validator_for(schema, default=None):
        class Validator:
            def __init__(self, wrapper):
                self.wrapper = wrapper

            def iter_errors(self, instance):
                return [FakeError("not ok")]

        return Validator

    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(
        sv,
        "_load_schema",
        lambda version: {"$schema": "x", "definitions": {"Thing": {}}},
    )
    monkeypatch.setattr(sv, "Draft202012Validator", object())
    monkeypatch.setattr(
        sv,
        "validators",
        SimpleNamespace(validator_for=_validator_for),
    )

    checks = sv.validate_definition("Thing", {"name": "example"})

    assert checks[0]["status"] == "FAIL"
    assert "Schema validation failed" in checks[0]["message"]
    assert checks[0]["details"]["errors"] == ["not ok"]


def test_validate_definition_passes(monkeypatch):
    def _validator_for(schema, default=None):
        class Validator:
            def __init__(self, wrapper):
                self.wrapper = wrapper

            def iter_errors(self, instance):
                return []

        return Validator

    monkeypatch.setattr(sv, "HAVE_JSONSCHEMA", True)
    monkeypatch.setattr(
        sv,
        "_load_schema",
        lambda version: {"$schema": "x", "definitions": {"Thing": {}}},
    )
    monkeypatch.setattr(sv, "Draft202012Validator", object())
    monkeypatch.setattr(
        sv,
        "validators",
        SimpleNamespace(validator_for=_validator_for),
    )

    checks = sv.validate_definition("Thing", {"name": "example"})

    assert checks[0]["status"] == "PASS"
    assert "Schema validation passed" in checks[0]["message"]


def test_load_schema_uses_cache(monkeypatch):
    cached = {"$schema": "x", "definitions": {"Thing": {}}}
    monkeypatch.setitem(sv._SCHEMA_CACHE, "cached-version", cached)

    result = sv._load_schema("cached-version")

    assert result == cached
