from mcp_fuzzer.spec_guard import spec_checks


def test_check_tool_result_content_image_missing_fields():
    # Test image missing data
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "image", "mimeType": "image/png"}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-image-data" in ids

    # Test image missing mimeType
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "image", "data": "base64"}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-image-mime" in ids

def test_check_tool_result_content_audio_missing_fields(monkeypatch):
    monkeypatch.setenv("MCP_SPEC_SCHEMA_VERSION", "2025-11-25")
    # Test audio missing data
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "audio", "mimeType": "audio/mp3"}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-audio-data" in ids

    # Test audio missing mimeType
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "audio", "data": "base64"}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-audio-mime" in ids

def test_check_tool_result_content_resource_missing_fields():
    # Test resource missing all
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "resource", "resource": {}}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-resource-uri" in ids
    assert "tools-content-resource-body" in ids
    
    # Test resource not a dict
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "resource", "resource": "not-dict"}]}
    )
    ids = {check["id"] for check in checks}
    assert "tools-content-resource" in ids

def test_check_logging_notification_missing_params():
    checks = spec_checks.check_logging_notification({})
    assert any(c["id"] == "logging-params-missing" for c in checks)

def test_check_resource_templates_list_not_dict_or_list():
    checks = spec_checks.check_resource_templates_list(
        {"resourceTemplates": "not-list"}
    )
    assert checks[0]["id"] == "resources-templates-type"

    checks = spec_checks.check_resource_templates_list(
        {"resourceTemplates": ["not-dict"]}
    )
    assert checks[0]["id"] == "resources-templates-item"

def test_check_prompts_list_missing_prompts():
    checks = spec_checks.check_prompts_list({})
    assert checks[0]["id"] == "prompts-list-missing"
