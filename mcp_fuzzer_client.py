import argparse
import asyncio
import logging
import traceback
import uuid

import httpx
from rich.console import Console
from rich.table import Table

from mcp_fuzzer.strategies import make_fuzz_strategy_from_jsonschema
from mcp_fuzzer.client import get_tools_from_server

logging.basicConfig(level=logging.INFO)


async def fuzz_tool(url: str, tool, runs: int = 10):
    """Fuzz a tool by calling it with random/edge-case arguments."""
    results = []
    schema = tool.get("inputSchema", {})
    strategy = make_fuzz_strategy_from_jsonschema(schema)
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    for _ in range(runs):
        args = strategy.example()
        try:
            params = {"name": tool["name"], "arguments": args}
            payload = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "tools/call",
                "params": params,
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, headers=headers)
                try:
                    result = resp.json()
                except Exception:
                    # SSE fallback
                    for line in resp.text.splitlines():
                        if line.startswith("data:"):
                            import json

                            data_json = line[len("data:") :].strip()
                            result = json.loads(data_json)
                            break
                    else:
                        logging.warning(
                            "Server returned a non-JSON (or SSE) response for tool call. Appending dummy result."
                        )
                        result = {"error": "Non-JSON response"}
            results.append({"args": args, "result": result})
        except Exception as e:
            results.append(
                {"args": args, "exception": str(e), "traceback": traceback.format_exc()}
            )
    return results


async def main():
    parser = argparse.ArgumentParser(description="MCP Fuzzer Client (JSON-RPC 2.0)")
    parser.add_argument(
        "--url",
        required=True,
        help="URL of the MCP server's JSON-RPC endpoint (e.g., http://localhost:8000/rpc)",
    )
    parser.add_argument(
        "--runs", type=int, default=10, help="Number of fuzzing runs per tool"
    )
    args = parser.parse_args()

    tools = get_tools_from_server(args.url)
    if not tools:
        logging.warning("Server returned an empty list of tools. Exiting.")
        return

    summary = {}
    for tool in tools:
        logging.info(f"Fuzzing tool: {tool['name']}")
        try:
            results = await fuzz_tool(args.url, tool, args.runs)
            exceptions = [r for r in results if "exception" in r]
            summary[tool["name"]] = {
                "total_runs": args.runs,
                "exceptions": len(exceptions),
                "example_exception": exceptions[0] if exceptions else None,
            }
        except Exception as e:
            summary[tool["name"]] = {"error": str(e)}

    # Print summary using rich
    console = Console()
    table = Table(title="Fuzzing Summary")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Total Runs", justify="right")
    table.add_column("Exceptions", justify="right")
    table.add_column("Example Exception", style="red")
    table.add_column("Error", style="magenta")

    for tool, result in summary.items():
        error = result.get("error", "")
        total_runs = str(result.get("total_runs", ""))
        exceptions = str(result.get("exceptions", ""))
        example_exception = ""
        if result.get("example_exception"):
            ex = result["example_exception"]
            example_exception = ex.get("exception", "")
        table.add_row(tool, total_runs, exceptions, example_exception, error)

    console.print(table)


if __name__ == "__main__":
    asyncio.run(main())
