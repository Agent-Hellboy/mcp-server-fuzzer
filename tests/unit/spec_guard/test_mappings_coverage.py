
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
