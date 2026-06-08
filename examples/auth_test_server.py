#!/usr/bin/env python3
"""Authenticated MCP server example using the official Python MCP SDK.

The MCP app is implemented with `mcp.server.fastmcp.FastMCP` from
https://github.com/modelcontextprotocol/python-sdk. A small ASGI wrapper
provides an OAuth client-credentials token endpoint and requires a Bearer token
only for calls to `secure_tool`, so e2e tests fuzz an authenticated tool rather
than fuzzing the auth endpoint itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import secrets
from collections.abc import Awaitable, Callable
from typing import Any, AsyncIterator
from urllib.parse import parse_qs

import anyio
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Message, Receive, Scope, Send


LOGGER = logging.getLogger(__name__)
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class AuthState:
    def __init__(self, client_id: str, client_secret: str, access_token: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.token_requests = 0
        self.authorized_tool_calls = 0
        self.unauthorized_tool_calls = 0


class SecureToolAuthMiddleware:
    """Require bearer auth only for JSON-RPC calls to secure_tool."""

    def __init__(self, app: ASGIApp, state: AuthState):
        self.app = app
        self.state = state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        body = await self._read_body(receive)
        request = self._decode_json(body)
        if self._is_secure_tool_call(request):
            if not self._has_valid_bearer_token(scope):
                self.state.unauthorized_tool_calls += 1
                await self._send_unauthorized_tool_response(send, request.get("id"))
                return
            self.state.authorized_tool_calls += 1

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

    def _decode_json(self, body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _is_secure_tool_call(self, request: dict[str, Any]) -> bool:
        params = request.get("params")
        return (
            request.get("method") == "tools/call"
            and isinstance(params, dict)
            and params.get("name") == "secure_tool"
        )

    def _has_valid_bearer_token(self, scope: Scope) -> bool:
        headers = {
            key.decode("latin1").lower(): value.decode("latin1")
            for key, value in scope.get("headers", [])
        }
        expected = f"Bearer {self.state.access_token}"
        return secrets.compare_digest(headers.get("authorization", ""), expected)

    async def _send_unauthorized_tool_response(
        self, send: Send, request_id: Any
    ) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32001, "message": "Unauthorized"},
            }
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
        "mcp-fuzzer-auth-e2e",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
    )

    @mcp.tool()
    def secure_tool(msg: str = "") -> str:
        """Echo text after bearer auth succeeds."""
        return f"secure ok: {msg}"

    return mcp


def build_app(state: AuthState) -> Starlette:
    mcp = build_mcp_server()

    async def token(request: Request) -> JSONResponse:
        if not _has_valid_client_auth(request, state):
            return JSONResponse(
                {"error": "invalid_client"},
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="mcp-fuzzer-e2e"'},
            )

        body = (await request.body()).decode("utf-8")
        form = parse_qs(body)
        if form.get("grant_type") != ["client_credentials"]:
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=400,
            )

        state.token_requests += 1
        return JSONResponse(
            {
                "access_token": state.access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "tools.read",
            }
        )

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    async def metrics(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "token_requests": state.token_requests,
                "authorized_tool_calls": state.authorized_tool_calls,
                "unauthorized_tool_calls": state.unauthorized_tool_calls,
            }
        )

    secure_mcp_app = SecureToolAuthMiddleware(mcp.streamable_http_app(), state)

    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/metrics", metrics, methods=["GET"]),
            Route("/oauth/token", token, methods=["POST"]),
            Mount("/mcp", app=secure_mcp_app),
        ],
        lifespan=lifespan,
    )


def _has_valid_client_auth(request: Request, state: AuthState) -> bool:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header.removeprefix("Basic ")).decode()
        client_id, client_secret = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    valid_id = secrets.compare_digest(client_id, state.client_id)
    valid_secret = secrets.compare_digest(client_secret, state.client_secret)
    return valid_id and valid_secret


def main() -> int:
    parser = argparse.ArgumentParser(description="Authenticated MCP e2e server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--client-id", default="mcp-fuzzer")
    parser.add_argument("--client-secret", default="mcp-fuzzer-secret")
    parser.add_argument("--access-token", default="mcp-fuzzer-access-token")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    state = AuthState(args.client_id, args.client_secret, args.access_token)
    app = build_app(state)
    LOGGER.info("Serving auth MCP e2e server at http://%s:%s", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
