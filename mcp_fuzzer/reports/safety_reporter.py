#!/usr/bin/env python3
"""
Safety Reporter for MCP Fuzzer

Handles all safety system reporting including blocked operations,
safety statistics, and safety data export.
"""

import logging
from datetime import datetime
from typing import Any, Dict

from rich.console import Console
from rich.table import Table


class SafetyReporter:
    """Handles all safety system reporting functionality."""

    def __init__(self):
        self.console = Console()
        self.safety_filter = None
        self.system_blocker = None

        # Try to import safety components
        try:
            from ..safety_system.safety import safety_filter

            self.safety_filter = safety_filter
        except ImportError:
            logging.debug("Safety filter not available")

        try:
            from ..safety_system.system_blocker import (
                get_blocked_operations,
                is_system_blocking_active,
            )

            self.get_blocked_operations = get_blocked_operations
            self.is_system_blocking_active = is_system_blocking_active
        except ImportError:
            logging.debug("System blocker not available")

    def print_safety_summary(self):
        """Print safety statistics in a compact format."""
        if not self.safety_filter:
            self.console.print(
                (
                    "\n[yellow]\U000026a0 Safety system not available for "
                    "reporting[/yellow]"
                )
            )
            return

        try:
            stats = self.safety_filter.get_safety_statistics()

            if stats["total_operations_blocked"] == 0:
                self.console.print(
                    (
                        "\n[green]\U00002705 No operations were blocked by "
                        "safety system[/green]"
                    )
                )
                return

            self.console.print(
                "\n[bold yellow]\U0001f6e1 Safety Statistics[/bold yellow]"
            )
            self.console.print(
                f"Total Operations Blocked: {stats['total_operations_blocked']}"
            )
            self.console.print(f"Unique Tools Blocked: {stats['unique_tools_blocked']}")
            self.console.print(f"Risk Assessment: {stats['risk_assessment'].upper()}")

            if stats["most_blocked_tool"]:
                self.console.print(
                    (
                        f"Most Blocked Tool: {stats['most_blocked_tool']} "
                        f"({stats['most_blocked_tool_count']} times)"
                    )
                )

            if stats["dangerous_content_breakdown"]:
                self.console.print("\nDangerous Content Types:")
                for content_type, count in stats["dangerous_content_breakdown"].items():
                    self.console.print(f"  • {content_type}: {count}")

        except Exception as e:
            self.console.print(
                f"\n[yellow]\U000026a0 Error getting safety statistics: {e}[/yellow]"
            )

    def print_safety_system_summary(self):
        """Print summary of safety system blocked operations."""
        if not self.safety_filter:
            self.console.print(
                (
                    "\n[yellow]\U000026a0 Safety system not available for detailed "
                    "reporting[/yellow]"
                )
            )
            return

        try:
            safety_summary = self.safety_filter.get_blocked_operations_summary()

            if safety_summary["total_blocked"] == 0:
                self.console.print(
                    (
                        "\n[green]\U00002705 No operations were blocked by safety "
                        "system[/green]"
                    )
                )
                return

            self.console.print(
                (
                    "\n[bold red]\U0001f6ab Safety System Blocked Operations Summary"
                    "[/bold red]"
                )
            )
            self.console.print(
                f"Blocked {safety_summary['total_blocked']} dangerous operations:\n"
            )

            # Create table for safety blocks
            table = Table(title="Safety System Blocks During Fuzzing")
            table.add_column("Tool", style="red", no_wrap=True)
            table.add_column("Count", style="yellow")
            table.add_column("Reason", style="dim")

            for tool, count in safety_summary["tools_blocked"].items():
                # Find the reason for this tool
                reason = "Unknown"
                for op in self.safety_filter.blocked_operations:
                    if op["tool_name"] == tool:
                        reason = op["reason"]
                        break

                table.add_row(tool, str(count), reason)

            self.console.print(table)

            # Show dangerous content breakdown
            if safety_summary["dangerous_content_types"]:
                self.console.print("\n[bold]Dangerous Content Types Blocked:[/bold]")
                for content_type, count in safety_summary[
                    "dangerous_content_types"
                ].items():
                    self.console.print(f"• {content_type}: {count} instances")

            # Show examples of blocked operations
            if safety_summary["tools_blocked"]:
                self.console.print("\n[bold]Example Blocked Operations:[/bold]")
                for op in self.safety_filter.blocked_operations[:3]:  # Show first 3
                    tool = op["tool_name"]
                    reason = op["reason"]
                    args_preview = (
                        str(op["arguments"])[:100] + "..."
                        if len(str(op["arguments"])) > 100
                        else str(op["arguments"])
                    )
                    self.console.print(f"• {tool}: {reason}")
                    self.console.print(f"  Args: {args_preview}")
                    self.console.print()

        except Exception as e:
            self.console.print(
                (
                    f"\n[yellow]\U000026a0 Error getting safety system summary: "
                    f"{e}[/yellow]"
                )
            )

    def print_blocked_operations_summary(self):
        """Print summary of blocked system operations."""
        if not hasattr(self, "get_blocked_operations"):
            self.console.print(
                (
                    "\n[yellow]\U000026a0 System blocker not available for "
                    "reporting[/yellow]"
                )
            )
            return

        try:
            blocked_ops = self.get_blocked_operations()

            # Status line about system-level safety
            try:
                if self.is_system_blocking_active():
                    self.console.print(
                        "\n[green]\U0001f6e1 System-level safety system enabled[/green]"
                    )
            except Exception:
                pass

            if not blocked_ops:
                # If system safety is disabled, clarify that nothing was monitored
                try:
                    safety_active = self.is_system_blocking_active()
                except Exception:
                    safety_active = True
                if not safety_active:
                    self.console.print(
                        (
                            "\n[yellow]\U0001f6e1 System-level safety system disabled; "
                            "no system operations were monitored[/yellow]"
                        )
                    )
                else:
                    self.console.print(
                        (
                            "\n[green]\U0001f6e1 No dangerous system "
                            "operations detected during fuzzing[/green]"
                        )
                    )
                return

            self.console.print(
                "\n[bold red]\U0001f6ab Blocked System Operations Summary[/bold red]"
            )
            self.console.print(
                f"Prevented {len(blocked_ops)} dangerous operations during fuzzing:\n"
            )

            # Create table for blocked operations
            table = Table(title="System Operations Blocked During Fuzzing")
            table.add_column("Operation", style="red", no_wrap=True)
            table.add_column("Command", style="yellow")
            table.add_column("Arguments", style="dim")
            table.add_column("Time", style="dim")

            for op in blocked_ops:
                # Extract time (just the time part) with error handling
                timestamp = op.get("timestamp", "")
                try:
                    if "T" in timestamp:
                        time_part = timestamp.split("T")[1].split(".")[0]  # HH:MM:SS
                    else:
                        time_part = timestamp
                except (IndexError, AttributeError):
                    time_part = "Unknown"

                # Determine operation type
                command = op.get("command", "unknown")
                args = op.get("args", "")

                if command in ["xdg-open", "open", "start"]:
                    operation_type = "\U0001f310 Browser/URL Open"
                elif command in ["firefox", "chrome", "chromium", "safari", "edge"]:
                    operation_type = "\U0001f310 Browser Launch"
                else:
                    operation_type = "\U000026a0 System Command"

                table.add_row(
                    operation_type,
                    command,
                    args[:50] + "..." if len(args) > 50 else args,
                    time_part,
                )

            self.console.print(table)

            # Summary by operation type
            browser_opens = sum(
                1
                for op in blocked_ops
                if op.get("command") in ["xdg-open", "open", "start"]
            )
            browser_launches = sum(
                1
                for op in blocked_ops
                if op.get("command")
                in ["firefox", "chrome", "chromium", "safari", "edge", "opera", "brave"]
            )

            self.console.print("\n[bold]Breakdown:[/bold]")
            self.console.print(f"• Browser/URL opens blocked: {browser_opens}")
            self.console.print(f"• Direct browser launches blocked: {browser_launches}")
            other_commands = len(blocked_ops) - browser_opens - browser_launches
            self.console.print(f"• Other system commands blocked: {other_commands}")

        except Exception as e:
            self.console.print(
                (
                    f"\n[yellow]\U000026a0 Error getting blocked operations summary: "
                    f"{e}[/yellow]"
                )
            )

    def print_comprehensive_safety_report(self):
        """Print a comprehensive safety report including all safety blocks."""
        self.console.print("\n" + "=" * 80)
        self.console.print(
            "[bold blue]\U0001f6e1 COMPREHENSIVE SAFETY REPORT[/bold blue]"
        )
        self.console.print("=" * 80)

        # System-level safety status
        try:
            if (
                hasattr(self, "is_system_blocking_active")
                and self.is_system_blocking_active()
            ):
                self.console.print(
                    "[green]\U00002705 System-level safety system: ACTIVE[/green]"
                )
            else:
                self.console.print(
                    "[yellow]\U000026a0 System-level safety system: INACTIVE[/yellow]"
                )
        except Exception:
            self.console.print(
                "[yellow]\U000026a0 System-level safety system: UNKNOWN STATUS[/yellow]"
            )

        # Safety system status
        try:
            if self.safety_filter:
                safety_summary = self.safety_filter.get_blocked_operations_summary()
                if safety_summary["total_blocked"] > 0:
                    self.console.print(
                        (
                            "[green]\U00002705 Safety system: ACTIVE (blocked "
                            f"{safety_summary['total_blocked']} operations)"
                            "[/green]"
                        )
                    )
                else:
                    self.console.print(
                        (
                            "[green]\U00002705 Safety system: ACTIVE "
                            "(no operations blocked)[/green]"
                        )
                    )
            else:
                self.console.print(
                    "[yellow]\U000026a0 Safety system: STATUS UNKNOWN[/yellow]"
                )
        except Exception:
            self.console.print(
                "[yellow]\U000026a0 Safety system: STATUS UNKNOWN[/yellow]"
            )

        self.console.print("\n" + "-" * 80)

        # Print both summaries
        self.print_blocked_operations_summary()
        self.print_safety_system_summary()

        # Print safety statistics
        self.print_safety_summary()

        self.console.print("\n" + "=" * 80)
        self.console.print("[bold green]\U0001f6e1 Safety Report Complete[/bold green]")
        self.console.print("=" * 80)

    def get_comprehensive_safety_data(self) -> Dict[str, Any]:
        """Get comprehensive safety data for reporting."""
        safety_data = {
            "timestamp": datetime.now().isoformat(),
            "system_safety": {},
            "safety_system": {},
        }

        # System-level safety data
        try:
            if hasattr(self, "get_blocked_operations"):
                blocked_ops = self.get_blocked_operations()
                safety_data["system_safety"] = {
                    "active": hasattr(self, "is_system_blocking_active")
                    and self.is_system_blocking_active(),
                    "blocked_operations": blocked_ops,
                    "total_blocked": len(blocked_ops),
                }
        except Exception as e:
            safety_data["system_safety"]["error"] = str(e)

        # Safety system data
        try:
            if self.safety_filter:
                safety_data["safety_system"] = {
                    "active": True,
                    "summary": self.safety_filter.get_blocked_operations_summary(),
                    "statistics": self.safety_filter.get_safety_statistics(),
                    "blocked_operations": self.safety_filter.blocked_operations,
                }
            else:
                safety_data["safety_system"]["active"] = False
        except Exception as e:
            safety_data["safety_system"]["error"] = str(e)

        return safety_data

    def has_safety_data(self) -> bool:
        """Check if there's any safety data available."""
        try:
            if self.safety_filter and self.safety_filter.blocked_operations:
                return True
            if hasattr(self, "get_blocked_operations"):
                blocked_ops = self.get_blocked_operations()
                return len(blocked_ops) > 0
            return False
        except Exception:
            return False

    def export_safety_data(self, filename: str = None) -> str:
        """Export safety data to JSON file."""
        if not self.safety_filter:
            logging.warning("Safety filter not available for export")
            return ""

        try:
            return self.safety_filter.export_safety_data(filename)
        except Exception as e:
            logging.error(f"Failed to export safety data: {e}")
            return ""
