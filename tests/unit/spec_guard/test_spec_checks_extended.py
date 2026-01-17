"""Extended tests for spec_checks.py to improve coverage."""

import pytest
from mcp_fuzzer.spec_guard.spec_checks import (
    check_tool_schema_fields,
    check_tool_result_content,
    check_logging_notification,
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
    check_sse_event_text,
)


class TestCheckToolSchemaFields:
    """Test check_tool_schema_fields function."""

    def test_no_input_schema(self):
        """Test tool with no inputSchema."""
        result = check_tool_schema_fields({})
        assert result == []

    def test_non_dict_input_schema(self):
        """Test tool with non-dict inputSchema."""
        result = check_tool_schema_fields({"inputSchema": "not a dict"})
        assert result == []

    def test_invalid_schema_type(self):
        """Test tool with non-string $schema."""
        result = check_tool_schema_fields({"inputSchema": {"$schema": 123}})
        assert len(result) == 1
        assert result[0]["id"] == "tool-schema-$schema"

    def test_invalid_defs_type(self):
        """Test tool with non-object $defs."""
        result = check_tool_schema_fields({"inputSchema": {"$defs": "not a dict"}})
        assert len(result) == 1
        assert result[0]["id"] == "tool-schema-$defs"

    def test_invalid_additional_properties(self):
        """Test tool with invalid additionalProperties."""
        result = check_tool_schema_fields(
            {"inputSchema": {"additionalProperties": "invalid"}}
        )
        assert len(result) == 1
        assert result[0]["id"] == "tool-schema-additional-properties"

    def test_valid_additional_properties_bool(self):
        """Test tool with valid boolean additionalProperties."""
        result = check_tool_schema_fields(
            {"inputSchema": {"additionalProperties": True}}
        )
        assert result == []

    def test_valid_additional_properties_dict(self):
        """Test tool with valid dict additionalProperties."""
        result = check_tool_schema_fields(
            {"inputSchema": {"additionalProperties": {"type": "string"}}}
        )
        assert result == []


class TestCheckToolResultContent:
    """Test check_tool_result_content function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_tool_result_content("not a dict")
        assert result == []

    def test_no_content_key(self):
        """Test result without content key."""
        result = check_tool_result_content({"other": "data"})
        assert result == []

    def test_non_array_content(self):
        """Test result with non-array content."""
        result = check_tool_result_content({"content": "not an array"})
        assert len(result) == 1
        assert result[0]["id"] == "tools-content-array"

    def test_empty_content_array(self):
        """Test result with empty content array."""
        result = check_tool_result_content({"content": []})
        assert len(result) == 1
        assert result[0]["id"] == "tools-content-empty"

    def test_non_dict_content_item(self):
        """Test result with non-dict content item."""
        result = check_tool_result_content({"content": ["not a dict"]})
        assert any(c["id"] == "tools-content-item" for c in result)

    def test_content_item_missing_type(self):
        """Test content item missing type."""
        result = check_tool_result_content({"content": [{"text": "hello"}]})
        assert any(c["id"] == "tools-content-type" for c in result)

    def test_text_content_missing_text(self):
        """Test text content missing text field."""
        result = check_tool_result_content({"content": [{"type": "text"}]})
        assert any(c["id"] == "tools-content-text" for c in result)

    def test_text_content_empty_text(self):
        """Test text content with empty text field."""
        result = check_tool_result_content({"content": [{"type": "text", "text": ""}]})
        assert any(c["id"] == "tools-content-text" for c in result)

    def test_image_content_missing_data(self):
        """Test image content missing data field."""
        result = check_tool_result_content(
            {"content": [{"type": "image", "mimeType": "image/png"}]}
        )
        assert any(c["id"] == "tools-content-image-data" for c in result)

    def test_image_content_missing_mimetype(self):
        """Test image content missing mimeType field."""
        result = check_tool_result_content(
            {"content": [{"type": "image", "data": "base64..."}]}
        )
        assert any(c["id"] == "tools-content-image-mime" for c in result)

    def test_audio_content_missing_data(self):
        """Test audio content missing data field."""
        result = check_tool_result_content(
            {"content": [{"type": "audio", "mimeType": "audio/mp3"}]}
        )
        assert any(c["id"] == "tools-content-audio-data" for c in result)

    def test_audio_content_missing_mimetype(self):
        """Test audio content missing mimeType field."""
        result = check_tool_result_content(
            {"content": [{"type": "audio", "data": "base64..."}]}
        )
        assert any(c["id"] == "tools-content-audio-mime" for c in result)

    def test_resource_content_non_dict_resource(self):
        """Test resource content with non-dict resource."""
        result = check_tool_result_content(
            {"content": [{"type": "resource", "resource": "not a dict"}]}
        )
        assert any(c["id"] == "tools-content-resource" for c in result)

    def test_resource_content_missing_uri(self):
        """Test resource content missing uri."""
        result = check_tool_result_content(
            {
                "content": [
                    {
                        "type": "resource",
                        "resource": {"mimeType": "text/plain", "text": "data"},
                    }
                ]
            }
        )
        assert any(c["id"] == "tools-content-resource-uri" for c in result)

    def test_resource_content_missing_mimetype(self):
        """Test resource content missing mimeType is allowed."""
        result = check_tool_result_content(
            {
                "content": [
                    {
                        "type": "resource",
                        "resource": {"uri": "file://test", "text": "data"},
                    }
                ]
            }
        )
        assert not any(c["id"] == "tools-content-resource-mime" for c in result)

    def test_resource_content_missing_body(self):
        """Test resource content missing text or blob."""
        result = check_tool_result_content(
            {
                "content": [
                    {
                        "type": "resource",
                        "resource": {
                            "uri": "file://test",
                            "mimeType": "text/plain",
                        },
                    }
                ]
            }
        )
        assert any(c["id"] == "tools-content-resource-body" for c in result)

    def test_unknown_content_type(self):
        """Test unknown content type generates warning."""
        result = check_tool_result_content({"content": [{"type": "custom_type"}]})
        assert any(c["id"] == "tools-content-unknown-type" for c in result)
        # Should be a warning, not a failure
        assert any(c.get("status") == "WARN" for c in result)

    def test_is_error_without_text_message(self):
        """Test isError=true without text error message."""
        result = check_tool_result_content(
            {
                "isError": True,
                "content": [
                    {"type": "image", "data": "base64", "mimeType": "image/png"}
                ],
            }
        )
        assert any(c["id"] == "tools-error-text" for c in result)

    def test_is_error_with_text_message(self):
        """Test isError=true with proper text error message."""
        result = check_tool_result_content(
            {"isError": True, "content": [{"type": "text", "text": "Error occurred"}]}
        )
        # Should not have tools-error-text failure
        assert not any(c["id"] == "tools-error-text" for c in result)


class TestCheckLoggingNotification:
    """Test check_logging_notification function."""

    def test_no_params(self):
        """Test payload without params."""
        result = check_logging_notification({})
        assert any(c["id"] == "logging-params-missing" for c in result)

    def test_params_none(self):
        """Test payload with None params."""
        result = check_logging_notification({"params": None})
        assert any(c["id"] == "logging-params-missing" for c in result)

    def test_non_dict_params(self):
        """Test payload with non-dict params."""
        result = check_logging_notification({"params": "not a dict"})
        assert len(result) == 1
        assert result[0]["id"] == "logging-params-type"

    def test_invalid_level_type(self):
        """Test payload with non-string level."""
        result = check_logging_notification({"params": {"level": 123}})
        assert any(c["id"] == "logging-level-type" for c in result)

    def test_invalid_message_type(self):
        """Test payload with non-string logger."""
        result = check_logging_notification({"params": {"logger": 123}})
        assert any(c["id"] == "logging-logger-type" for c in result)
        assert any(c["id"] == "logging-level-missing" for c in result)
        assert any(c["id"] == "logging-data-missing" for c in result)

    def test_valid_logging_notification(self):
        """Test valid logging notification."""
        result = check_logging_notification(
            {"params": {"level": "INFO", "data": "Test"}}
        )
        assert result == []


class TestCheckResourcesList:
    """Test check_resources_list function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_resources_list("not a dict")
        assert result == []

    def test_missing_resources(self):
        """Test result missing resources key."""
        result = check_resources_list({})
        assert len(result) == 1
        assert result[0]["id"] == "resources-list-missing"

    def test_non_array_resources(self):
        """Test result with non-array resources."""
        result = check_resources_list({"resources": "not an array"})
        assert len(result) == 1
        assert result[0]["id"] == "resources-list-type"

    def test_non_dict_resource_item(self):
        """Test resource item that is not a dict."""
        result = check_resources_list({"resources": ["not a dict"]})
        assert any(c["id"] == "resources-list-item" for c in result)

    def test_resource_missing_uri(self):
        """Test resource missing uri."""
        result = check_resources_list({"resources": [{"name": "test"}]})
        assert any(c["id"] == "resources-list-uri" for c in result)

    def test_resource_missing_name(self):
        """Test resource missing name."""
        result = check_resources_list({"resources": [{"uri": "file://test"}]})
        assert any(c["id"] == "resources-list-name" for c in result)

    def test_valid_resources(self):
        """Test valid resources list."""
        result = check_resources_list(
            {"resources": [{"uri": "file://test", "name": "Test"}]}
        )
        assert result == []


class TestCheckResourcesRead:
    """Test check_resources_read function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_resources_read("not a dict")
        assert result == []

    def test_missing_contents(self):
        """Test result missing contents key."""
        result = check_resources_read({})
        assert len(result) == 1
        assert result[0]["id"] == "resources-read-missing"

    def test_non_array_contents(self):
        """Test result with non-array contents."""
        result = check_resources_read({"contents": "not an array"})
        assert len(result) == 1
        assert result[0]["id"] == "resources-read-type"

    def test_empty_contents(self):
        """Test result with empty contents array."""
        result = check_resources_read({"contents": []})
        assert len(result) == 1
        assert result[0]["id"] == "resources-read-empty"

    def test_non_dict_content_item(self):
        """Test content item that is not a dict."""
        result = check_resources_read({"contents": ["not a dict"]})
        assert any(c["id"] == "resources-read-item" for c in result)

    def test_content_missing_uri(self):
        """Test content missing uri."""
        result = check_resources_read({"contents": [{"text": "data"}]})
        assert any(c["id"] == "resources-read-uri" for c in result)

    def test_content_missing_body(self):
        """Test content missing text and blob."""
        result = check_resources_read({"contents": [{"uri": "file://test"}]})
        assert any(c["id"] == "resources-read-body" for c in result)

    def test_valid_contents(self):
        """Test valid contents."""
        result = check_resources_read(
            {"contents": [{"uri": "file://test", "text": "data"}]}
        )
        assert result == []


class TestCheckResourceTemplatesList:
    """Test check_resource_templates_list function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_resource_templates_list("not a dict")
        assert result == []

    def test_no_resource_templates(self):
        """Test result without resourceTemplates key."""
        result = check_resource_templates_list({})
        assert any(c["id"] == "resources-templates-missing" for c in result)

    def test_non_array_templates(self):
        """Test result with non-array resourceTemplates."""
        result = check_resource_templates_list(
            {"resourceTemplates": "not an array"}
        )
        assert len(result) == 1
        assert result[0]["id"] == "resources-templates-type"

    def test_non_dict_template_item(self):
        """Test template item that is not a dict."""
        result = check_resource_templates_list(
            {"resourceTemplates": ["not a dict"]}
        )
        assert any(c["id"] == "resources-templates-item" for c in result)

    def test_template_missing_uri_template(self):
        """Test template missing uriTemplate."""
        result = check_resource_templates_list(
            {"resourceTemplates": [{"name": "test"}]}
        )
        assert any(c["id"] == "resources-templates-uri" for c in result)

    def test_valid_templates(self):
        """Test valid templates."""
        result = check_resource_templates_list(
            {"resourceTemplates": [{"name": "tmpl", "uriTemplate": "file://template"}]}
        )
        assert result == []


class TestCheckPromptsList:
    """Test check_prompts_list function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_prompts_list("not a dict")
        assert result == []

    def test_missing_prompts(self):
        """Test result missing prompts key."""
        result = check_prompts_list({})
        assert len(result) == 1
        assert result[0]["id"] == "prompts-list-missing"

    def test_non_array_prompts(self):
        """Test result with non-array prompts."""
        result = check_prompts_list({"prompts": "not an array"})
        assert len(result) == 1
        assert result[0]["id"] == "prompts-list-type"


class TestCheckPromptsGet:
    """Test check_prompts_get function."""

    def test_non_dict_result(self):
        """Test with non-dict result."""
        result = check_prompts_get("not a dict")
        assert result == []

    def test_missing_messages(self):
        """Test result missing messages key."""
        result = check_prompts_get({})
        assert len(result) == 1
        assert result[0]["id"] == "prompts-get-missing"

    def test_non_array_messages(self):
        """Test result with non-array messages."""
        result = check_prompts_get({"messages": "not an array"})
        assert len(result) == 1
        assert result[0]["id"] == "prompts-get-type"


class TestCheckSseEventText:
    """Test check_sse_event_text function."""

    def test_valid_event(self):
        """Test valid SSE event."""
        result = check_sse_event_text("data: {\"foo\": \"bar\"}")
        assert result == []

    def test_missing_data_prefix(self):
        """Test SSE event without data prefix."""
        result = check_sse_event_text("{\"foo\": \"bar\"}")
        # Should warn about missing data field
        assert any(c.get("status") == "WARN" for c in result)
