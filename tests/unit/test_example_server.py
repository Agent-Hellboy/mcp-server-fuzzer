from __future__ import annotations

from starlette.testclient import TestClient

from examples.test_server import build_app


def test_server_initiated_methods_middleware_handles_stub_batch():
    app = build_app()

    with TestClient(app) as client:
        response = client.post(
            "/mcp/",
            json=[
                {"jsonrpc": "2.0", "id": 1, "method": "roots/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "sampling/createMessage",
                    "params": {},
                },
                {
                    "jsonrpc": "2.0",
                    "method": "elicitation/create",
                    "params": {},
                },
            ],
        )

    assert response.status_code == 200
    assert response.json() == [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "roots": [
                    {"uri": "file:///workspace", "name": "workspace"},
                    {"uri": "file:///tmp/sandbox", "name": "sandbox"},
                ]
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "role": "assistant",
                "content": {"type": "text", "text": "stub sampling response"},
                "model": "stub-model",
                "stopReason": "endTurn",
            },
        },
    ]
