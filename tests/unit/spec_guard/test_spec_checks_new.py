"""Tests for new spec check functions added in MCP 2025-11-25 coverage."""

from __future__ import annotations

import pytest

from mcp_fuzzer.spec_guard.spec_checks import (
    check_cancelled_notification,
    check_completion_complete,
    check_list_changed_notification,
    check_progress_notification,
    check_resources_updated_notification,
    check_subscribe_result,
    check_unsubscribe_result,
)


# ---------------------------------------------------------------------------
# completion/complete
# ---------------------------------------------------------------------------


def test_completion_complete_valid():
    result = {"completion": {"values": ["foo", "bar"], "hasMore": False, "total": 2}}
    assert check_completion_complete(result) == []


def test_completion_complete_minimal():
    result = {"completion": {"values": []}}
    assert check_completion_complete(result) == []


def test_completion_complete_not_dict():
    assert check_completion_complete("string") == []


def test_completion_complete_missing_completion_key():
    checks = check_completion_complete({})
    ids = [c["id"] for c in checks]
    assert "completion-missing" in ids


def test_completion_complete_completion_not_dict():
    checks = check_completion_complete({"completion": "bad"})
    ids = [c["id"] for c in checks]
    assert "completion-type" in ids


def test_completion_complete_missing_values():
    checks = check_completion_complete({"completion": {}})
    ids = [c["id"] for c in checks]
    assert "completion-values-missing" in ids


def test_completion_complete_values_not_array():
    checks = check_completion_complete({"completion": {"values": "bad"}})
    ids = [c["id"] for c in checks]
    assert "completion-values-type" in ids


def test_completion_complete_values_non_string_item():
    checks = check_completion_complete({"completion": {"values": [1, "ok"]}})
    ids = [c["id"] for c in checks]
    assert "completion-values-item" in ids


def test_completion_complete_has_more_non_bool():
    checks = check_completion_complete(
        {"completion": {"values": [], "hasMore": "yes"}}
    )
    ids = [c["id"] for c in checks]
    assert "completion-has-more-type" in ids


def test_completion_complete_total_non_int():
    checks = check_completion_complete(
        {"completion": {"values": [], "total": 3.5}}
    )
    ids = [c["id"] for c in checks]
    assert "completion-total-type" in ids


def test_completion_complete_total_bool_rejected():
    checks = check_completion_complete({"completion": {"values": [], "total": True}})
    ids = [c["id"] for c in checks]
    assert "completion-total-type" in ids


# ---------------------------------------------------------------------------
# resources/subscribe
# ---------------------------------------------------------------------------


def test_subscribe_result_valid_empty():
    assert check_subscribe_result({}) == []


def test_subscribe_result_not_dict():
    checks = check_subscribe_result("nope")
    ids = [c["id"] for c in checks]
    assert "subscribe-result-type" in ids


# ---------------------------------------------------------------------------
# resources/unsubscribe
# ---------------------------------------------------------------------------


def test_unsubscribe_result_valid_empty():
    assert check_unsubscribe_result({}) == []


def test_unsubscribe_result_not_dict():
    checks = check_unsubscribe_result(42)
    ids = [c["id"] for c in checks]
    assert "unsubscribe-result-type" in ids


# ---------------------------------------------------------------------------
# notifications/progress
# ---------------------------------------------------------------------------


def test_progress_notification_valid():
    payload = {"params": {"progressToken": "tok-1", "progress": 50, "total": 100}}
    assert check_progress_notification(payload) == []


def test_progress_notification_integer_token():
    payload = {"params": {"progressToken": 42, "progress": 0.5}}
    assert check_progress_notification(payload) == []


def test_progress_notification_params_not_dict():
    checks = check_progress_notification({"params": "bad"})
    ids = [c["id"] for c in checks]
    assert "progress-params-type" in ids


def test_progress_notification_missing_token():
    checks = check_progress_notification({"params": {"progress": 1}})
    ids = [c["id"] for c in checks]
    assert "progress-token-missing" in ids


def test_progress_notification_bool_token_rejected():
    checks = check_progress_notification(
        {"params": {"progressToken": True, "progress": 1}}
    )
    ids = [c["id"] for c in checks]
    assert "progress-token-type" in ids


def test_progress_notification_missing_progress():
    checks = check_progress_notification({"params": {"progressToken": "t"}})
    ids = [c["id"] for c in checks]
    assert "progress-value-missing" in ids


def test_progress_notification_bool_progress_rejected():
    checks = check_progress_notification(
        {"params": {"progressToken": "t", "progress": False}}
    )
    ids = [c["id"] for c in checks]
    assert "progress-value-type" in ids


def test_progress_notification_non_numeric_total():
    checks = check_progress_notification(
        {"params": {"progressToken": "t", "progress": 1, "total": "big"}}
    )
    ids = [c["id"] for c in checks]
    assert "progress-total-type" in ids


# ---------------------------------------------------------------------------
# notifications/cancelled
# ---------------------------------------------------------------------------


def test_cancelled_notification_valid():
    payload = {"params": {"requestId": "req-1", "reason": "user cancelled"}}
    assert check_cancelled_notification(payload) == []


def test_cancelled_notification_integer_request_id():
    payload = {"params": {"requestId": 99}}
    assert check_cancelled_notification(payload) == []


def test_cancelled_notification_params_not_dict():
    checks = check_cancelled_notification({"params": None})
    ids = [c["id"] for c in checks]
    assert "cancelled-params-type" in ids


def test_cancelled_notification_missing_request_id():
    checks = check_cancelled_notification({"params": {}})
    ids = [c["id"] for c in checks]
    assert "cancelled-request-id-missing" in ids


def test_cancelled_notification_bool_request_id_rejected():
    checks = check_cancelled_notification({"params": {"requestId": True}})
    ids = [c["id"] for c in checks]
    assert "cancelled-request-id-type" in ids


def test_cancelled_notification_non_string_reason():
    checks = check_cancelled_notification({"params": {"requestId": "r", "reason": 42}})
    ids = [c["id"] for c in checks]
    assert "cancelled-reason-type" in ids


# ---------------------------------------------------------------------------
# list_changed notifications (generic)
# ---------------------------------------------------------------------------


def test_list_changed_no_params():
    assert check_list_changed_notification({}) == []


def test_list_changed_empty_params():
    assert check_list_changed_notification({"params": {}}) == []


def test_list_changed_params_not_dict():
    checks = check_list_changed_notification({"params": "bad"})
    ids = [c["id"] for c in checks]
    assert "list-changed-params-type" in ids


# ---------------------------------------------------------------------------
# notifications/resources/updated
# ---------------------------------------------------------------------------


def test_resources_updated_valid():
    payload = {"params": {"uri": "file:///foo/bar"}}
    assert check_resources_updated_notification(payload) == []


def test_resources_updated_params_not_dict():
    checks = check_resources_updated_notification({"params": 42})
    ids = [c["id"] for c in checks]
    assert "resources-updated-params-type" in ids


def test_resources_updated_missing_uri():
    checks = check_resources_updated_notification({"params": {}})
    ids = [c["id"] for c in checks]
    assert "resources-updated-uri-missing" in ids


def test_resources_updated_empty_uri():
    checks = check_resources_updated_notification({"params": {"uri": ""}})
    ids = [c["id"] for c in checks]
    assert "resources-updated-uri-missing" in ids
