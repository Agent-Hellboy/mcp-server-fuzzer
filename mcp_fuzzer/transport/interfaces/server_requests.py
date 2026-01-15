"""Helpers for server-initiated requests handled by the client."""

from __future__ import annotations

from typing import Any


def is_server_request(payload: Any) -> bool:
    """Return True when payload looks like a JSON-RPC 2.0 server->client request."""
    return (
        isinstance(payload, dict)
        and payload.get("jsonrpc") == "2.0"
        and "method" in payload
        and "id" in payload
        and "result" not in payload
        and "error" not in payload
    )


def build_sampling_create_message_response(
    request_id: Any,
    *,
    model: str = "mcp-fuzzer",
    text: str = "mcp-fuzzer sampling response",
) -> dict[str, Any]:
    """Build a minimal CreateMessageResult response for sampling/createMessage."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "model": model,
            "role": "assistant",
            "content": {"type": "text", "text": text},
        },
    }


__all__ = ["is_server_request", "build_sampling_create_message_response"]
