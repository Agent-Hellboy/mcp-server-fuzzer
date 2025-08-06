#!/usr/bin/env python3
"""
Unified MCP Fuzzer Client

This module provides a comprehensive client for fuzzing both MCP tools and protocol types
using the modular fuzzer structure.
"""

import argparse
import asyncio
import json
import logging
import traceback
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

from .fuzzer.protocol_fuzzer import ProtocolFuzzer
from .fuzzer.tool_fuzzer import ToolFuzzer
from .transport import create_transport

logging.basicConfig(level=logging.INFO)


class UnifiedMCPFuzzerClient:
    """Unified client for fuzzing MCP tools and protocol types."""

    def __init__(self, transport):
        self.transport = transport
        self.tool_fuzzer = ToolFuzzer()
        self.protocol_fuzzer = ProtocolFuzzer()
        self.console = Console()

    # ============================================================================
    # TOOL FUZZING METHODS
    # ============================================================================

    async def fuzz_tool(
        self, tool: Dict[str, Any], runs: int = 10
    ) -> List[Dict[str, Any]]:
        """Fuzz a tool by calling it with random/edge-case arguments."""
        results = []

        for i in range(runs):
            try:
                # Generate fuzz arguments using the fuzzer
                fuzz_result = self.tool_fuzzer.fuzz_tool(tool, 1)[
                    0
                ]  # Get single result
                args = fuzz_result["args"]

                logging.info(
                    f"Fuzzing {tool['name']} (run {i + 1}/{runs}) with args: {args}"
                )
                result = await self.transport.call_tool(tool["name"], args)
                results.append({"args": args, "result": result})
            except Exception as e:
                logging.warning(f"Exception during fuzzing {tool['name']}: {e}")
                results.append(
                    {
                        "args": args,
                        "exception": str(e),
                        "traceback": traceback.format_exc(),
                    }
                )

        return results

    async def fuzz_all_tools(
        self, runs_per_tool: int = 10
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz all tools from the server."""
        # Get tools from server
        try:
            tools = await self.transport.get_tools()
            if not tools:
                logging.warning("Server returned an empty list of tools.")
                return {}
            logging.info(f"Found {len(tools)} tools to fuzz")
        except Exception as e:
            logging.error(f"Failed to get tools from server: {e}")
            return {}

        all_results = {}

        for tool in tools:
            tool_name = tool.get("name", "unknown")
            logging.info(f"Starting to fuzz tool: {tool_name}")

            try:
                results = await self.fuzz_tool(tool, runs_per_tool)
                all_results[tool_name] = results

                # Calculate statistics
                exceptions = [r for r in results if "exception" in r]

                logging.info(
                    f"Completed fuzzing {tool_name}: {len(exceptions)} exceptions out of {runs_per_tool} runs"
                )

            except Exception as e:
                logging.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results

    # ============================================================================
    # PROTOCOL FUZZING METHODS
    # ============================================================================

    async def fuzz_protocol_type(
        self, protocol_type: str, runs: int = 10
    ) -> List[Dict[str, Any]]:
        """Fuzz a specific protocol type."""
        results = []

        for i in range(runs):
            try:
                # Generate fuzz data using the fuzzer
                fuzz_results = self.protocol_fuzzer.fuzz_protocol_type(protocol_type, 1)
                fuzz_data = fuzz_results[0]["fuzz_data"]

                logging.info(
                    f"Fuzzing {protocol_type} (run {i + 1}/{runs}) with data: {json.dumps(fuzz_data, indent=2)[:200]}..."
                )

                # Send the fuzz data through transport
                result = await self._send_protocol_request(protocol_type, fuzz_data)

                results.append(
                    {"fuzz_data": fuzz_data, "result": result, "success": True}
                )

            except Exception as e:
                logging.warning(f"Exception during fuzzing {protocol_type}: {e}")
                results.append(
                    {
                        "fuzz_data": fuzz_data if "fuzz_data" in locals() else None,
                        "exception": str(e),
                        "traceback": traceback.format_exc(),
                        "success": False,
                    }
                )

        return results

    async def _send_protocol_request(
        self, protocol_type: str, data: Dict[str, Any]
    ) -> Any:
        """Send a protocol request based on the type."""
        if protocol_type == "InitializeRequest":
            return await self._send_initialize_request(data)
        elif protocol_type == "ProgressNotification":
            return await self._send_progress_notification(data)
        elif protocol_type == "CancelNotification":
            return await self._send_cancel_notification(data)
        elif protocol_type == "ListResourcesRequest":
            return await self._send_list_resources_request(data)
        elif protocol_type == "ReadResourceRequest":
            return await self._send_read_resource_request(data)
        elif protocol_type == "SetLevelRequest":
            return await self._send_set_level_request(data)
        elif protocol_type == "CreateMessageRequest":
            return await self._send_create_message_request(data)
        elif protocol_type == "ListPromptsRequest":
            return await self._send_list_prompts_request(data)
        elif protocol_type == "GetPromptRequest":
            return await self._send_get_prompt_request(data)
        elif protocol_type == "ListRootsRequest":
            return await self._send_list_roots_request(data)
        elif protocol_type == "SubscribeRequest":
            return await self._send_subscribe_request(data)
        elif protocol_type == "UnsubscribeRequest":
            return await self._send_unsubscribe_request(data)
        elif protocol_type == "CompleteRequest":
            return await self._send_complete_request(data)
        else:
            # Generic JSON-RPC request
            return await self._send_generic_request(data)

    async def _send_initialize_request(self, data: Dict[str, Any]) -> Any:
        """Send an initialize request."""
        return await self.transport.send_request("initialize", data.get("params", {}))

    async def _send_progress_notification(self, data: Dict[str, Any]) -> Any:
        """Send a progress notification."""
        await self.transport.send_request(
            "notifications/progress", data.get("params", {})
        )
        return {"status": "notification_sent"}

    async def _send_cancel_notification(self, data: Dict[str, Any]) -> Any:
        """Send a cancel notification."""
        await self.transport.send_request(
            "notifications/cancelled", data.get("params", {})
        )
        return {"status": "notification_sent"}

    async def _send_list_resources_request(self, data: Dict[str, Any]) -> Any:
        """Send a list resources request."""
        return await self.transport.send_request(
            "resources/list", data.get("params", {})
        )

    async def _send_read_resource_request(self, data: Dict[str, Any]) -> Any:
        """Send a read resource request."""
        return await self.transport.send_request(
            "resources/read", data.get("params", {})
        )

    async def _send_set_level_request(self, data: Dict[str, Any]) -> Any:
        """Send a set level request."""
        return await self.transport.send_request(
            "logging/setLevel", data.get("params", {})
        )

    async def _send_create_message_request(self, data: Dict[str, Any]) -> Any:
        """Send a create message request."""
        return await self.transport.send_request(
            "sampling/createMessage", data.get("params", {})
        )

    async def _send_list_prompts_request(self, data: Dict[str, Any]) -> Any:
        """Send a list prompts request."""
        return await self.transport.send_request("prompts/list", data.get("params", {}))

    async def _send_get_prompt_request(self, data: Dict[str, Any]) -> Any:
        """Send a get prompt request."""
        return await self.transport.send_request("prompts/get", data.get("params", {}))

    async def _send_list_roots_request(self, data: Dict[str, Any]) -> Any:
        """Send a list roots request."""
        return await self.transport.send_request("roots/list", data.get("params", {}))

    async def _send_subscribe_request(self, data: Dict[str, Any]) -> Any:
        """Send a subscribe request."""
        return await self.transport.send_request(
            "resources/subscribe", data.get("params", {})
        )

    async def _send_unsubscribe_request(self, data: Dict[str, Any]) -> Any:
        """Send an unsubscribe request."""
        return await self.transport.send_request(
            "resources/unsubscribe", data.get("params", {})
        )

    async def _send_complete_request(self, data: Dict[str, Any]) -> Any:
        """Send a complete request."""
        return await self.transport.send_request(
            "completion/complete", data.get("params", {})
        )

    async def _send_generic_request(self, data: Dict[str, Any]) -> Any:
        """Send a generic JSON-RPC request."""
        method = data.get("method", "unknown")
        params = data.get("params", {})
        return await self.transport.send_request(method, params)

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz all protocol types."""
        protocol_types = [
            "InitializeRequest",
            "ProgressNotification",
            "CancelNotification",
            "ListResourcesRequest",
            "ReadResourceRequest",
            "SetLevelRequest",
            "GenericJSONRPCRequest",
            "CreateMessageRequest",
            "ListPromptsRequest",
            "GetPromptRequest",
            "ListRootsRequest",
            "SubscribeRequest",
            "UnsubscribeRequest",
            "CompleteRequest",
        ]

        all_results = {}

        for protocol_type in protocol_types:
            logging.info(f"Starting to fuzz protocol type: {protocol_type}")

            try:
                results = await self.fuzz_protocol_type(protocol_type, runs_per_type)
                all_results[protocol_type] = results

                # Calculate statistics
                successful = len([r for r in results if r.get("success", False)])
                exceptions = len([r for r in results if not r.get("success", False)])

                logging.info(
                    f"Completed fuzzing {protocol_type}: {successful} successful, {exceptions} exceptions out of {runs_per_type} runs"
                )

            except Exception as e:
                logging.error(f"Failed to fuzz protocol type {protocol_type}: {e}")
                all_results[protocol_type] = [{"error": str(e)}]

        return all_results

    # ============================================================================
    # SUMMARY METHODS
    # ============================================================================

    def print_tool_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print a summary of tool fuzzing results."""
        table = Table(title="MCP Tool Fuzzing Summary")
        table.add_column("Tool", style="cyan", no_wrap=True)
        table.add_column("Total Runs", justify="right")
        table.add_column("Exceptions", justify="right")
        table.add_column("Success Rate", justify="right")
        table.add_column("Example Exception", style="red")
        table.add_column("Error", style="magenta")

        for tool_name, tool_results in results.items():
            if not tool_results:
                table.add_row(tool_name, "0", "0", "0%", "", "")
                continue

            # Check if there's a general error
            if len(tool_results) == 1 and "error" in tool_results[0]:
                table.add_row(
                    tool_name,
                    "0",
                    "0",
                    "0%",
                    "",
                    tool_results[0]["error"][:50] + "..."
                    if len(tool_results[0]["error"]) > 50
                    else tool_results[0]["error"],
                )
                continue

            total_runs = len(tool_results)
            exceptions = len([r for r in tool_results if "exception" in r])
            successful = total_runs - exceptions
            success_rate = (successful / total_runs * 100) if total_runs > 0 else 0

            # Find example exception
            example_exception = ""
            for result in tool_results:
                if "exception" in result:
                    ex = result["exception"]
                    example_exception = ex[:50] + "..." if len(ex) > 50 else ex
                    break

            table.add_row(
                tool_name,
                str(total_runs),
                str(exceptions),
                f"{success_rate:.1f}%",
                example_exception,
                "",
            )

        self.console.print(table)

    def print_protocol_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print a summary of protocol fuzzing results."""
        table = Table(title="MCP Protocol Fuzzing Summary")
        table.add_column("Protocol Type", style="cyan", no_wrap=True)
        table.add_column("Total Runs", justify="right")
        table.add_column("Successful", justify="right")
        table.add_column("Exceptions", justify="right")
        table.add_column("Success Rate", justify="right")
        table.add_column("Example Exception", style="red")
        table.add_column("Error", style="magenta")

        for protocol_type, protocol_results in results.items():
            if not protocol_results:
                table.add_row(protocol_type, "0", "0", "0", "0%", "", "")
                continue

            # Check if there's a general error
            if len(protocol_results) == 1 and "error" in protocol_results[0]:
                table.add_row(
                    protocol_type,
                    "0",
                    "0",
                    "0",
                    "0%",
                    "",
                    protocol_results[0]["error"][:50] + "..."
                    if len(protocol_results[0]["error"]) > 50
                    else protocol_results[0]["error"],
                )
                continue

            total_runs = len(protocol_results)
            successful = len([r for r in protocol_results if r.get("success", False)])
            exceptions = total_runs - successful
            success_rate = (successful / total_runs * 100) if total_runs > 0 else 0

            # Find example exception
            example_exception = ""
            for result in protocol_results:
                if not result.get("success", False) and "exception" in result:
                    ex = result["exception"]
                    example_exception = ex[:50] + "..." if len(ex) > 50 else ex
                    break

            table.add_row(
                protocol_type,
                str(total_runs),
                str(successful),
                str(exceptions),
                f"{success_rate:.1f}%",
                example_exception,
                "",
            )

        self.console.print(table)

    def print_overall_summary(
        self,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
    ):
        """Print overall summary statistics."""
        # Tool statistics
        total_tools = len(tool_results)
        tools_with_errors = len(
            [r for r in tool_results.values() if len(r) == 1 and "error" in r[0]]
        )
        tools_with_exceptions = len(
            [
                r
                for r in tool_results.values()
                if len(r) > 1 and any("exception" in res for res in r)
            ]
        )

        # Protocol statistics
        total_protocol_types = len(protocol_results)
        protocol_types_with_errors = len(
            [r for r in protocol_results.values() if len(r) == 1 and "error" in r[0]]
        )
        protocol_types_with_exceptions = len(
            [
                r
                for r in protocol_results.values()
                if len(r) > 1 and any(not res.get("success", False) for res in r)
            ]
        )

        self.console.print("\n[bold]Overall Statistics:[/bold]")
        self.console.print(f"Total tools tested: {total_tools}")
        self.console.print(f"Tools with errors: {tools_with_errors}")
        self.console.print(f"Tools with exceptions: {tools_with_exceptions}")
        self.console.print(f"Total protocol types tested: {total_protocol_types}")
        self.console.print(f"Protocol types with errors: {protocol_types_with_errors}")
        self.console.print(
            f"Protocol types with exceptions: {protocol_types_with_exceptions}"
        )


async def main():
    """Main function for the unified MCP fuzzer client."""
    parser = argparse.ArgumentParser(
        description="Unified MCP Fuzzer Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz tools only
  python -m mcp_fuzzer.unified_client --mode tools --protocol http --endpoint http://localhost:8000/mcp/ --runs 10

  # Fuzz protocol types only
  python -m mcp_fuzzer.unified_client --mode protocol --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 5

  # Fuzz both tools and protocols
  python -m mcp_fuzzer.unified_client --mode both --protocol http --endpoint http://localhost:8000/mcp/ --runs 10 --runs-per-type 5

  # Fuzz specific protocol type
  python -m mcp_fuzzer.unified_client --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000/mcp/
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["tools", "protocol", "both"],
        default="both",
        help="Fuzzing mode: 'tools' for tool fuzzing, 'protocol' for protocol fuzzing, 'both' for both (default: both)",
    )
    parser.add_argument(
        "--protocol",
        choices=["http", "sse", "stdio", "websocket"],
        default="http",
        help="Transport protocol to use (default: http)",
    )
    parser.add_argument(
        "--endpoint",
        required=True,
        help="Server endpoint (URL for http/sse/websocket, command for stdio)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of fuzzing runs per tool (default: 10)",
    )
    parser.add_argument(
        "--runs-per-type",
        type=int,
        default=5,
        help="Number of fuzzing runs per protocol type (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--protocol-type",
        help="Fuzz only a specific protocol type (when mode is protocol)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create transport
    try:
        transport = create_transport(
            protocol=args.protocol, endpoint=args.endpoint, timeout=args.timeout
        )
        logging.info(f"Created {args.protocol} transport for endpoint: {args.endpoint}")
    except Exception as e:
        logging.error(f"Failed to create transport: {e}")
        return

    # Create unified client
    client = UnifiedMCPFuzzerClient(transport)

    # Run fuzzing based on mode
    if args.mode == "tools":
        logging.info("Fuzzing tools only")
        tool_results = await client.fuzz_all_tools(args.runs)
        client.print_tool_summary(tool_results)

    elif args.mode == "protocol":
        if args.protocol_type:
            logging.info(f"Fuzzing specific protocol type: {args.protocol_type}")
            protocol_results = await client.fuzz_protocol_type(
                args.protocol_type, args.runs_per_type
            )
            client.print_protocol_summary({args.protocol_type: protocol_results})
        else:
            logging.info("Fuzzing all protocol types")
            protocol_results = await client.fuzz_all_protocol_types(args.runs_per_type)
            client.print_protocol_summary(protocol_results)

    elif args.mode == "both":
        logging.info("Fuzzing both tools and protocols")

        # Fuzz tools
        logging.info("Starting tool fuzzing...")
        tool_results = await client.fuzz_all_tools(args.runs)
        client.print_tool_summary(tool_results)

        # Fuzz protocols
        logging.info("Starting protocol fuzzing...")
        protocol_results = await client.fuzz_all_protocol_types(args.runs_per_type)
        client.print_protocol_summary(protocol_results)

        # Print overall summary
        client.print_overall_summary(tool_results, protocol_results)


if __name__ == "__main__":
    asyncio.run(main())
