#!/usr/bin/env python3
"""
Pytest configuration file for component-based test selection.
"""

import os
import sys
from typing import List, Optional

import pytest


def pytest_configure(config):
    """Configure pytest with custom component selection logic."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection based on component selection.

    This allows running tests for specific components that have changed.
    """
    selected_components = []
    selected_markers = []

    # Check for component selection from command line
    if config.getoption("--component"):
        selected_components = config.getoption("--component").split(",")

    # Auto-detect changed components from git if requested
    if config.getoption("--changed-only"):
        import subprocess

        try:
            # Get changed files from git
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            changed_files = result.stdout.strip().split("\n")

            # Extract components from changed files
            for file_path in changed_files:
                if file_path.startswith("mcp_fuzzer/"):
                    parts = file_path.split("/")
                    if len(parts) > 1:
                        component = parts[1]
                        if component not in selected_components:
                            selected_components.append(component)
        except (subprocess.SubprocessError, IndexError):
            pass

    # Skip test selection if no components specified
    if not selected_components:
        return

    # Convert component names to pytest markers
    for component in selected_components:
        marker = component.replace("/", "_").lower()
        selected_markers.append(marker)

    # Create skip marker for tests that don't match the selected components
    skip_marker = pytest.mark.skip(
        reason=f"Test not in selected components: {', '.join(selected_components)}"
    )

    # Apply skip marker to tests not matching the selected components
    for item in items:
        # Get explicit markers
        markers = {m.name for m in item.iter_markers()}

        # For unittest TestCase classes, add implicit markers based on file path
        if not markers:
            # Detect component from file path
            test_path = str(item.path)
            if "/unit/" in test_path:
                if "/auth/" in test_path:
                    markers.add("auth")
                elif "/cli/" in test_path:
                    markers.add("cli")
                elif "/client/" in test_path:
                    markers.add("client")
                elif "/config/" in test_path:
                    markers.add("config")
                elif "/fuzz_engine/fuzzer/" in test_path:
                    markers.add("fuzz_engine")
                    markers.add("fuzzer")
                elif "/fuzz_engine/runtime/" in test_path:
                    markers.add("fuzz_engine")
                    markers.add("runtime")
                elif "/fuzz_engine/strategy/" in test_path:
                    markers.add("fuzz_engine")
                    markers.add("strategy")
                elif "/fuzz_engine/" in test_path:
                    markers.add("fuzz_engine")
                elif "/safety_system/" in test_path:
                    markers.add("safety_system")
                elif "/transport/" in test_path:
                    markers.add("transport")
            elif "/integration/" in test_path:
                markers.add("integration")

        # Skip if no matching markers
        if not markers.intersection(selected_markers) and "integration" not in markers:
            item.add_marker(skip_marker)


def pytest_addoption(parser):
    """Add component selection options to pytest."""
    parser.addoption(
        "--component",
        action="store",
        default="",
        help="Run tests for specific components (comma-separated)",
    )
    parser.addoption(
        "--changed-only",
        action="store_true",
        default=False,
        help="Run tests only for components with changes in git",
    )
