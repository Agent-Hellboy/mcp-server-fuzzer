#!/usr/bin/env python3
"""Simple MCP test server using the official Python MCP SDK."""

from __future__ import annotations

import logging
import os
import json
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
import uvicorn
from mcp import types
from mcp.server.fastmcp import FastMCP
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Message, Receive, Scope, Send


LOGGER = logging.getLogger(__name__)
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

REQUIRED_AUTH_SCHEME = "Bearer"
BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.getenv("BIND_PORT", "8000"))
REQUIRED_TOKEN = os.getenv("REQUIRED_TOKEN", "secret123")

_CURRENT_LOG_LEVEL: str = "info"
_SUBSCRIBED_URIS: set[str] = set()


class SecureToolAuthMiddleware:
    """Require bearer auth only for calls to secure_tool."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        body = await self._read_body(receive)
        request = self._decode_json(body)
        if self._is_secure_tool_call(request) and not self._has_valid_auth(scope):
            request_id = request.get("id") if isinstance(request, dict) else None
            await self._send_unauthorized(send, request_id)
            return

        await self.app(scope, self._replay_body(body), send)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            chunks.append(message.get("body", b""))
            more_body = bool(message.get("more_body", False))
        return b"".join(chunks)

    def _replay_body(self, body: bytes) -> Receive:
        sent = False

        async def receive() -> Message:
            nonlocal sent
            if sent:
                await anyio.sleep(0)
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        return receive

    def _decode_json(self, body: bytes) -> Any:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {}
        return payload

    def _is_secure_tool_call(self, request: Any) -> bool:
        if isinstance(request, list):
            return any(self._is_secure_tool_call(item) for item in request)
        if not isinstance(request, dict):
            return False
        params = request.get("params")
        return (
            request.get("method") == "tools/call"
            and isinstance(params, dict)
            and params.get("name") == "secure_tool"
        )

    def _has_valid_auth(self, scope: Scope) -> bool:
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        expected = f"{REQUIRED_AUTH_SCHEME} {REQUIRED_TOKEN}"
        return secrets.compare_digest(headers.get("authorization", ""), expected)

    async def _send_unauthorized(self, send: Send, request_id: Any) -> None:
        body = (
            '{"jsonrpc":"2.0","id":'
            f"{json.dumps(request_id)},"
            '"error":{"code":-32001,"message":"Unauthorized"}}'
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def build_mcp_server() -> FastMCP:
    mcp = FastMCP(
        "mcp-fuzzer-test-server",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
    )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def test_tool(message: str = "default", count: int = 1) -> str:
        """Return the supplied message and count."""
        return f"Test tool called with message: {message}, count: {count}"

    @mcp.tool()
    def echo_tool(text: str = "default") -> str:
        """Echo text back to the caller."""
        return f"Echo: {text}"

    @mcp.tool()
    def secure_tool(msg: str = "") -> str:
        """Return a response only after middleware verifies bearer auth."""
        return f"Secure OK: {msg}"

    # ------------------------------------------------------------------
    # Resources (static + template)
    # ------------------------------------------------------------------

    @mcp.resource("test://static/hello")
    def hello_resource() -> str:
        """A static hello resource."""
        return "Hello from the MCP test server!"

    @mcp.resource("test://static/info")
    def info_resource() -> str:
        """Server info as a resource."""
        return json.dumps({"server": "mcp-fuzzer-test-server", "version": "1.0.0"})

    @mcp.resource("test://items/{item_id}", name="item")
    def item_resource(item_id: str) -> str:
        """A parameterised item resource."""
        return f"Item: {item_id}"

    # ------------------------------------------------------------------
    # Prompts
    # ------------------------------------------------------------------

    @mcp.prompt(name="hello_prompt", description="Greet someone by name")
    def hello_prompt(name: str = "world") -> list[types.PromptMessage]:
        return [
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=f"Hello, {name}!"),
            )
        ]

    @mcp.prompt(name="summarise_prompt", description="Ask the model to summarise text")
    def summarise_prompt(text: str = "") -> list[types.PromptMessage]:
        return [
            types.PromptMessage(
                role="user",
                content=types.TextContent(
                    type="text",
                    text=f"Please summarise the following:\n\n{text}",
                ),
            )
        ]

    # ------------------------------------------------------------------
    # Completion  (completion/complete)
    # ------------------------------------------------------------------

    @mcp._mcp_server.completion()
    async def handle_completion(
        ref: types.PromptReference | types.ResourceTemplateReference,
        argument: types.CompletionArgument,
        context: types.CompletionContext | None,
    ) -> types.Completion | None:
        """Return completions for prompt arguments and resource template params."""
        arg_name = argument.name
        arg_value = argument.value

        if isinstance(ref, types.PromptReference):
            if ref.name == "hello_prompt" and arg_name == "name":
                candidates = ["Alice", "Bob", "Carol", "Dave"]
                values = [c for c in candidates if c.lower().startswith(arg_value.lower())]
                return types.Completion(values=values, total=len(values), hasMore=False)

        if isinstance(ref, types.ResourceTemplateReference):
            if arg_name == "item_id":
                candidates = ["apple", "banana", "cherry"]
                values = [c for c in candidates if c.startswith(arg_value)]
                return types.Completion(values=values, total=len(values), hasMore=False)

        return types.Completion(values=[], total=0, hasMore=False)

    # ------------------------------------------------------------------
    # Logging  (logging/setLevel)
    # ------------------------------------------------------------------

    @mcp._mcp_server.set_logging_level()
    async def handle_set_log_level(level: types.LoggingLevel) -> None:
        global _CURRENT_LOG_LEVEL
        _CURRENT_LOG_LEVEL = str(level)
        LOGGER.info("Log level set to %s", level)

    # ------------------------------------------------------------------
    # Resource subscriptions  (resources/subscribe, resources/unsubscribe)
    # ------------------------------------------------------------------

    @mcp._mcp_server.subscribe_resource()
    async def handle_subscribe(uri: AnyUrl) -> None:
        _SUBSCRIBED_URIS.add(str(uri))
        LOGGER.info("Subscribed to resource: %s", uri)

    @mcp._mcp_server.unsubscribe_resource()
    async def handle_unsubscribe(uri: AnyUrl) -> None:
        _SUBSCRIBED_URIS.discard(str(uri))
        LOGGER.info("Unsubscribed from resource: %s", uri)

    return mcp


def build_app() -> Starlette:
    mcp = build_mcp_server()

    async def health(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "healthy",
                "server": "mcp-fuzzer-test-server",
                "version": "1.0.0",
                "capabilities": [
                    "tools",
                    "resources",
                    "prompts",
                    "completion",
                    "logging",
                    "subscribe",
                ],
            }
        )

    async def lifespan(_: Starlette):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        debug=False,
        routes=[
            Route("/", health, methods=["GET"]),
            Route("/health", health, methods=["GET"]),
            Mount("/mcp", app=SecureToolAuthMiddleware(mcp.streamable_http_app())),
        ],
        lifespan=lifespan,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    LOGGER.info("Starting MCP test server on %s:%s", BIND_HOST, BIND_PORT)
    uvicorn.run(build_app(), host=BIND_HOST, port=BIND_PORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
