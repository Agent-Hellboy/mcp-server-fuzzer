#!/usr/bin/env python3
"""
Unified MCP Fuzzer Client

This module provides a comprehensive client for fuzzing both MCP tools and
protocol types using the modular fuzzer structure.
"""

import asyncio
import json
import logging
import traceback
from typing import Any, Dict, List, Optional


from .auth import AuthManager, load_auth_config, setup_auth_from_env
from .fuzz_engine.fuzzer import ToolFuzzer, ProtocolFuzzer
from .transport import create_transport
from .reports import FuzzerReporter


class UnifiedMCPFuzzerClient:
    """Unified client for fuzzing MCP tools and protocol types."""

    def __init__(
        self,
        transport,
        auth_manager: Optional[AuthManager] = None,
        tool_timeout: Optional[float] = None,
        reporter: Optional[FuzzerReporter] = None,
    ):
        self.transport = transport
        self.tool_fuzzer = ToolFuzzer()
        self.protocol_fuzzer = ProtocolFuzzer(transport)  # Pass transport
        self.reporter = reporter or FuzzerReporter()
        self.auth_manager = auth_manager or AuthManager()
        self.tool_timeout = tool_timeout

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

                # Get authentication for this tool
                auth_headers = self.auth_manager.get_auth_headers_for_tool(tool["name"])
                auth_params = self.auth_manager.get_auth_params_for_tool(tool["name"])

                # Merge auth params with tool arguments if needed
                if auth_params:
                    args.update(auth_params)

                # High-level run progress at INFO without arguments
                logging.info(f"Fuzzing {tool['name']} (run {i + 1}/{runs})")
                # Detailed arguments and headers at DEBUG only
                logging.debug(
                    f"Fuzzing {tool['name']} (run {i + 1}/{runs}) with args: {args}"
                )
                if auth_headers:
                    logging.debug(f"Using auth headers: {list(auth_headers.keys())}")

                # Enforce per-call timeout and allow immediate Ctrl-C
                try:
                    tool_task = None
                    # Prefer explicit tool-timeout passed via CLI; fall back to
                    # transport.timeout or 30s
                    tool_timeout = 30.0
                    if hasattr(self.transport, "timeout") and self.transport.timeout:
                        tool_timeout = float(self.transport.timeout)
                    if hasattr(self, "tool_timeout") and self.tool_timeout:
                        tool_timeout = float(self.tool_timeout)

                    # Create a task that can be cancelled
                    tool_task = asyncio.create_task(
                        self.transport.call_tool(tool["name"], args)
                    )

                    # Wait for the task with timeout and cancellation support
                    result = await asyncio.wait_for(tool_task, timeout=tool_timeout)

                except asyncio.CancelledError:
                    # Cancel the tool task if we're cancelled
                    if tool_task is not None:
                        tool_task.cancel()
                        try:
                            await asyncio.wait_for(tool_task, timeout=1.0)
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            pass
                    raise
                except asyncio.TimeoutError:
                    # Cancel the tool task on timeout
                    if tool_task is not None:
                        tool_task.cancel()
                        try:
                            await asyncio.wait_for(tool_task, timeout=1.0)
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            pass

                    results.append(
                        {
                            "args": args,
                            "exception": "timeout",
                            "timed_out": True,
                            "safety_blocked": False,
                            "safety_sanitized": False,
                        }
                    )
                    continue
                except Exception as e:
                    # Handle any other exceptions
                    if tool_task is not None:
                        tool_task.cancel()
                        try:
                            await asyncio.wait_for(tool_task, timeout=1.0)
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            pass

                    results.append(
                        {
                            "args": args,
                            "exception": str(e),
                            "safety_blocked": False,
                            "safety_sanitized": False,
                        }
                    )
                    continue

                # Check for safety information in the result
                safety_blocked = False
                safety_sanitized = False

                if isinstance(result, dict):
                    # Check for safety metadata
                    if "_meta" in result:
                        meta = result["_meta"]
                        safety_blocked = meta.get("safety_blocked", False)
                        safety_sanitized = meta.get("safety_sanitized", False)

                    # Also check if the result indicates it was blocked
                    if "content" in result and isinstance(result["content"], list):
                        for content_item in result["content"]:
                            if (
                                isinstance(content_item, dict)
                                and "text" in content_item
                            ):
                                text = content_item["text"]
                                if "[SAFETY BLOCKED]" in text or "[BLOCKED" in text:
                                    safety_blocked = True
                                    break

                results.append(
                    {
                        "args": args,
                        "result": result,
                        "safety_blocked": safety_blocked,
                        "safety_sanitized": safety_sanitized,
                    }
                )
            except Exception as e:
                logging.warning(f"Exception during fuzzing {tool['name']}: {e}")
                results.append(
                    {
                        "args": args,
                        "exception": str(e),
                        "traceback": traceback.format_exc(),
                        "safety_blocked": False,
                        "safety_sanitized": False,
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
        start_time = asyncio.get_event_loop().time()
        max_total_time = 300  # 5 minutes max for entire fuzzing session

        for i, tool in enumerate(tools):
            # Check if we're taking too long overall
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > max_total_time:
                logging.warning(
                    f"Fuzzing session taking too long ({elapsed:.1f}s), stopping early"
                )
                break

            tool_name = tool.get("name", "unknown")
            logging.info(f"Starting to fuzz tool: {tool_name} ({i + 1}/{len(tools)})")

            try:
                # Add a timeout for each individual tool
                max_tool_time = 60  # 1 minute max per tool

                tool_task = asyncio.create_task(self.fuzz_tool(tool, runs_per_tool))

                try:
                    results = await asyncio.wait_for(tool_task, timeout=max_tool_time)
                except asyncio.TimeoutError:
                    logging.warning(f"Tool {tool_name} took too long, cancelling")
                    tool_task.cancel()
                    try:
                        await asyncio.wait_for(tool_task, timeout=1.0)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        pass
                    results = [
                        {"error": "tool_timeout", "exception": "Tool fuzzing timed out"}
                    ]

                all_results[tool_name] = results

                # Calculate statistics
                exceptions = [r for r in results if "exception" in r]

                logging.info(
                    "Completed fuzzing %s: %d exceptions out of %d runs",
                    tool_name,
                    len(exceptions),
                    runs_per_tool,
                )

            except Exception as e:
                logging.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results

    async def fuzz_all_tools_both_phases(
        self, runs_per_phase: int = 5
    ) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Fuzz all tools in both realistic and aggressive phases."""
        # Use reporter for output instead of console
        if hasattr(self, "reporter") and self.reporter:
            self.reporter.console.print(
                "\n[bold blue]\U0001f680 Starting Two-Phase Tool Fuzzing[/bold blue]"
            )

        try:
            tools = await self.transport.get_tools()
            if not tools:
                if hasattr(self, "reporter") and self.reporter:
                    self.reporter.console.print(
                        "[yellow]\U000026a0  No tools available for fuzzing[/yellow]"
                    )
                return {}

            all_results = {}
            tool_fuzzer = ToolFuzzer()

            for tool in tools:
                tool_name = tool.get("name", "unknown")
                if hasattr(self, "reporter") and self.reporter:
                    self.reporter.console.print(
                        f"\n[cyan]\U0001f527 Two-phase fuzzing tool: {tool_name}[/cyan]"
                    )

                try:
                    # Run both phases for this tool
                    phase_results = tool_fuzzer.fuzz_tool_both_phases(
                        tool, runs_per_phase
                    )
                    all_results[tool_name] = phase_results

                    # Report phase statistics
                    for phase, results in phase_results.items():
                        successful = len(
                            [r for r in results if r.get("success", False)]
                        )
                        total = len(results)
                        if hasattr(self, "reporter") and self.reporter:
                            self.reporter.console.print(
                                (
                                    f"  {phase.title()} phase: "
                                    f"{successful}/{total} successful"
                                )
                            )

                except Exception as e:
                    logging.error(f"Error in two-phase fuzzing {tool_name}: {e}")
                    all_results[tool_name] = {"error": str(e)}

            return all_results

        except Exception as e:
            logging.error(f"Failed to fuzz all tools (two-phase): {e}")
            return {}

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
                fuzz_results = await self.protocol_fuzzer.fuzz_protocol_type(
                    protocol_type, 1
                )
                fuzz_data = fuzz_results[0]["fuzz_data"]

                preview = json.dumps(fuzz_data, indent=2)[:200]
                logging.info(
                    "Fuzzing %s (run %d/%d) with data: %s...",
                    protocol_type,
                    i + 1,
                    runs,
                    preview,
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
        """Send a progress notification as JSON-RPC notification (no id)."""
        params = data.get("params", {})
        if not isinstance(params, dict):
            logging.debug("Non-dict params for progress notification; coercing to {}")
            params = {}
        await self.transport.send_notification("notifications/progress", params)
        return {"status": "notification_sent"}

    async def _send_cancel_notification(self, data: Dict[str, Any]) -> Any:
        """Send a cancel notification as JSON-RPC notification (no id)."""
        params = data.get("params", {})
        if not isinstance(params, dict):
            logging.debug("Non-dict params for cancel notification; coercing to {}")
            params = {}
        await self.transport.send_notification("notifications/cancelled", params)
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
        """Fuzz all protocol types using the ProtocolFuzzer and group results."""
        try:
            # The protocol fuzzer now actually sends requests to the server
            return await self.protocol_fuzzer.fuzz_all_protocol_types(runs_per_type)
        except Exception as e:
            logging.error(f"Failed to fuzz all protocol types: {e}")
            return {}

    # ============================================================================
    # SUMMARY METHODS
    # ============================================================================

    def print_tool_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print a summary of tool fuzzing results."""
        self.reporter.print_tool_summary(results)

    def print_protocol_summary(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print a summary of protocol fuzzing results."""
        self.reporter.print_protocol_summary(results)

    def print_safety_statistics(self):
        """Print safety statistics in a compact format."""
        self.reporter.print_safety_summary()

    def print_safety_system_summary(self):
        """Print summary of safety system blocked operations."""
        self.reporter.print_safety_system_summary()

    def print_blocked_operations_summary(self):
        """Print summary of blocked system operations."""
        self.reporter.print_blocked_operations_summary()

    def print_overall_summary(
        self,
        tool_results: Dict[str, List[Dict[str, Any]]],
        protocol_results: Dict[str, List[Dict[str, Any]]],
    ):
        """Print overall summary statistics."""
        self.reporter.print_overall_summary(tool_results, protocol_results)

    async def cleanup(self):
        """Clean up resources, especially the transport."""
        if hasattr(self.transport, "close"):
            try:
                await self.transport.close()
            except Exception as e:
                logging.warning(f"Error during transport cleanup: {e}")

    def print_comprehensive_safety_report(self):
        """Print a comprehensive safety report including all safety blocks."""
        self.reporter.print_comprehensive_safety_report()


async def main():
    """Main function for the unified MCP fuzzer client.

    Command-line parsing is centralized in mcp_fuzzer.cli.args. We reuse that
    parser here to interpret any argv passed by the top-level CLI.
    """
    from .cli.args import create_argument_parser

    parser = create_argument_parser()
    args, _unknown = parser.parse_known_args()

    # Create transport
    try:
        transport = create_transport(
            protocol=args.protocol, endpoint=args.endpoint, timeout=args.timeout
        )
        logging.info(f"Created {args.protocol} transport for endpoint: {args.endpoint}")
    except Exception as e:
        logging.error(f"Failed to create transport: {e}")
        return

    # Set up authentication if requested
    auth_manager = None
    if hasattr(args, "auth_config") and args.auth_config:
        auth_manager = load_auth_config(args.auth_config)
        logging.info(f"Loaded auth config from: {args.auth_config}")
    elif hasattr(args, "auth_env") and args.auth_env:
        auth_manager = setup_auth_from_env()
        logging.info("Loaded auth from environment variables")

    # Create reporter
    reporter = FuzzerReporter(output_dir=getattr(args, "output_dir", "reports"))
    reporter.set_fuzzing_metadata(
        mode=args.mode,
        protocol=args.protocol,
        endpoint=args.endpoint,
        runs=args.runs,
        runs_per_type=getattr(args, "runs_per_type", None),
    )

    # Create unified client
    client = UnifiedMCPFuzzerClient(
        transport,
        auth_manager,
        tool_timeout=(args.tool_timeout if hasattr(args, "tool_timeout") else None),
        reporter=reporter,
    )

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

    # Print blocked operations summary
    client.print_blocked_operations_summary()

    # Show comprehensive safety report if requested
    if hasattr(args, "safety_report") and args.safety_report:
        client.print_comprehensive_safety_report()

    # Export safety data if requested
    if hasattr(args, "export_safety_data") and args.export_safety_data is not None:
        try:
            filename = client.reporter.export_safety_data(args.export_safety_data)
            if filename:
                logging.info(f"Safety data exported to: {filename}")
        except Exception as e:
            logging.error(f"Failed to export safety data: {e}")

    # Generate final comprehensive report
    try:
        report_file = reporter.generate_final_report(include_safety=True)
        logging.info(f"Final report generated: {report_file}")
    except Exception as e:
        logging.error(f"Failed to generate final report: {e}")

    # Clean up transport
    await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
