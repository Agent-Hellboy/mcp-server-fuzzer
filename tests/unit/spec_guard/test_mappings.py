import pytest

from mcp_fuzzer.spec_guard import mappings

def test_get_spec_checks_for_method_invalid_input():
    # Test None and empty string
    assert mappings.get_spec_checks_for_method(None, {}) == ([], None)
    assert mappings.get_spec_checks_for_method("", {}) == ([], None)
    # Test unknown method
    assert mappings.get_spec_checks_for_method("unknown/method", {}) == ([], None)

def test_get_spec_checks_for_protocol_type_generic():
    # Test GenericJSONRPCRequest dispatch
    # We need to mock the mapping or just rely on the fact that "tools/call" exists
    checks, scope = mappings.get_spec_checks_for_protocol_type(
        "GenericJSONRPCRequest", 
        {"content": []}, # partial payload for tools/call
        method="tools/call"
    )
    assert scope == "tools/call"
    
    # Test GenericJSONRPCRequest with unknown method
    checks, scope = mappings.get_spec_checks_for_protocol_type(
        "GenericJSONRPCRequest", 
        {}, 
        method="unknown"
    )
    assert checks == []
    assert scope is None

def test_get_spec_checks_for_protocol_type_mapped():
    # Test known protocol type
    # ListResourcesRequest maps to resources/list
    checks, scope = mappings.get_spec_checks_for_protocol_type(
        "ListResourcesRequest",
        {"resources": []}
    )
    assert scope == "resources/list"

    # Test unknown protocol type
    checks, scope = mappings.get_spec_checks_for_protocol_type(
        "UnknownProtocolType",
        {}
    )
    assert checks == []
    assert scope is None


@pytest.mark.parametrize("method,payload,expected_scope", [
    (
        "completion/complete",
        {"completion": {"values": ["a"]}},
        "completion/complete",
    ),
    (
        "resources/subscribe",
        {},
        "resources/subscribe",
    ),
    (
        "resources/unsubscribe",
        {},
        "resources/unsubscribe",
    ),
    (
        "notifications/progress",
        {"params": {"progressToken": "t", "progress": 1}},
        "notifications/progress",
    ),
    (
        "notifications/cancelled",
        {"params": {"requestId": "r"}},
        "notifications/cancelled",
    ),
    (
        "notifications/resources/list_changed",
        {},
        "notifications/resources/list_changed",
    ),
    (
        "notifications/resources/updated",
        {"params": {"uri": "file:///x"}},
        "notifications/resources/updated",
    ),
    (
        "notifications/prompts/list_changed",
        {},
        "notifications/prompts/list_changed",
    ),
    (
        "notifications/tools/list_changed",
        {},
        "notifications/tools/list_changed",
    ),
    (
        "notifications/roots/list_changed",
        {},
        "notifications/roots/list_changed",
    ),
])
def test_new_methods_in_method_check_map(method, payload, expected_scope):
    checks, scope = mappings.get_spec_checks_for_method(method, payload)
    assert scope == expected_scope


@pytest.mark.parametrize("protocol_type,expected_method", [
    ("ProgressNotification", "notifications/progress"),
    ("CancelledNotification", "notifications/cancelled"),
    ("ResourceListChangedNotification", "notifications/resources/list_changed"),
    ("ResourceUpdatedNotification", "notifications/resources/updated"),
    ("PromptListChangedNotification", "notifications/prompts/list_changed"),
    ("ToolListChangedNotification", "notifications/tools/list_changed"),
    ("RootsListChangedNotification", "notifications/roots/list_changed"),
    ("SubscribeRequest", "resources/subscribe"),
    ("UnsubscribeRequest", "resources/unsubscribe"),
    ("CompleteRequest", "completion/complete"),
])
def test_new_protocol_types_mapped(protocol_type, expected_method):
    _, scope = mappings.get_spec_checks_for_protocol_type(protocol_type, {})
    assert scope == expected_method
