"""Minimal StreamableHTTP MCP server using the official `mcp` SDK from PyPI.

Prereq:
  pip install mcp

Run:
  python3 examples/streamable_http_server.py --host 127.0.0.1 --port 3000
"""

import argparse
import logging
from typing import AsyncIterator

from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
import mcp.types as types
import anyio
import uvicorn


def build_app(json_response: bool = False) -> Starlette:
    app = Server("mcp-fuzzer-streamablehttp-example")

    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="start-notification-stream",
                description="Emit a short SSE notification stream and a final result",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "interval": {"type": "number", "default": 0.25},
                        "count": {"type": "integer", "default": 5},
                        "caller": {"type": "string", "default": "fuzzer"},
                    },
                },
            )
        ]

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        ctx = app.request_context
        interval = float(arguments.get("interval", 0.25))
        count = int(arguments.get("count", 5))
        caller = str(arguments.get("caller", "fuzzer"))

        for i in range(count):
            await ctx.session.send_log_message(
                level="info",
                data=f"[{i+1}/{count}] hello from {caller}",
                logger="stream",
                related_request_id=ctx.request_id,
            )
            if i < count - 1:
                await anyio.sleep(interval)

        return [
            types.TextContent(type="text", text=f"done: {count} events for {caller}")
        ]

    session_manager = StreamableHTTPSessionManager(app=app, json_response=json_response)

    async def handle_streamable_http(
        scope: Scope, receive: Receive, send: Send
    ) -> None:
        await session_manager.handle_request(scope, receive, send)

    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    return Starlette(
        debug=False,
        routes=[Mount("/mcp", app=handle_streamable_http)],
        lifespan=lifespan,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="StreamableHTTP MCP server example")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--json-response", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    app = build_app(json_response=args.json_response)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
