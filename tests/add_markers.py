#!/usr/bin/env python3
"""
Helper script to add pytest markers to all test files based on their location.
"""

import os
import re
import sys
from pathlib import Path

# Define marker mapping based on directory structure
COMPONENT_MARKERS = {
    "unit/auth": ["unit", "auth"],
    "unit/cli": ["unit", "cli"],
    "unit/client": ["unit", "client"],
    "unit/config": ["unit", "config"],
    "unit/fuzz_engine": ["unit", "fuzz_engine"],
    "unit/fuzz_engine/executor": ["unit", "fuzz_engine", "executor"],
    "unit/fuzz_engine/fuzzer": ["unit", "fuzz_engine", "fuzzer"],
    "unit/fuzz_engine/fuzzerreporter": ["unit", "fuzz_engine", "fuzzerreporter"],
    "unit/fuzz_engine/mutators": ["unit", "fuzz_engine", "mutators"],
    "unit/fuzz_engine/runtime": ["unit", "fuzz_engine", "runtime"],
    "unit/fuzz_engine/strategy": ["unit", "fuzz_engine", "strategy"],
    "unit/safety_system": ["unit", "safety_system"],
    "unit/transport": ["unit", "transport"],
    "integration": ["integration"],
}

# Import statement to add
IMPORT_STATEMENT = "\nimport pytest\n"
MARKER_TEMPLATE = "\npytestmark = [{}]\n"


def add_markers_to_file(file_path):
    """Add appropriate markers to a test file based on its location."""
    rel_path = str(file_path.relative_to(Path("tests")))
    parent_dir = "/".join(file_path.parent.parts[1:])

    # Determine which markers to apply based on directory
    markers = []
    # Choose the most specific (longest) matching prefix
    best_prefix = None
    for path_prefix in COMPONENT_MARKERS.keys():
        if parent_dir.startswith(path_prefix) and (
            best_prefix is None or len(path_prefix) > len(best_prefix)
        ):
            best_prefix = path_prefix
    if best_prefix:
        markers = COMPONENT_MARKERS[best_prefix]

    if not markers:
        print(f"Could not determine markers for {file_path}")
        return False

    # Read the file content
    with open(file_path, "r") as f:
        content = f.read()

    # Check if markers already exist; if so, try to merge missing markers
    if "pytestmark =" in content:
        mark_line_match = re.search(r"pytestmark\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if mark_line_match:
            existing_segment = mark_line_match.group(1)
            existing = set(
                m.strip().replace("pytest.mark.", "")
                for m in existing_segment.split(",")
                if m.strip()
            )
            missing = [m for m in markers if m not in existing]
            if missing:
                merged = list(existing) + missing
                merged_str = ", ".join([f"pytest.mark.{m}" for m in merged])
                new_line = f"pytestmark = [{merged_str}]"
                start, end = mark_line_match.span()
                content = content[:start] + new_line + content[end:]
            else:
                print(f"Markers already exist in {file_path}")
                return True

    # Add pytest import if needed
    if "import pytest" not in content:
        # Find the end of the imports or docstring (support both quote styles)
        module_header_end = re.search(r'("""|\'\'\').*?\1\s*', content, re.DOTALL)
        if module_header_end:
            insert_position = module_header_end.end()
            content = (
                content[:insert_position] + IMPORT_STATEMENT + content[insert_position:]
            )
        else:
            # If no docstring, add import after any other imports
            import_match = re.search(r"^import.*?$|^from.*?$", content, re.MULTILINE)
            if import_match:
                last_import = None
                for match in re.finditer(
                    r"^(?:import|from).*?$", content, re.MULTILINE
                ):
                    last_import = match
                insert_position = last_import.end() + 1
                content = (
                    content[:insert_position]
                    + "\n"
                    + IMPORT_STATEMENT
                    + content[insert_position:]
                )
            else:
                # If no imports, add after any shebang and file encoding declarations
                shebang_match = re.search(r"^#!.*?$", content, re.MULTILINE)
                if shebang_match:
                    insert_position = shebang_match.end() + 1
                    content = (
                        content[:insert_position]
                        + "\n"
                        + IMPORT_STATEMENT
                        + content[insert_position:]
                    )
                else:
                    # Otherwise, add to the beginning of the file
                    content = IMPORT_STATEMENT + content

    # Add markers
    marker_str = ", ".join([f"pytest.mark.{marker}" for marker in markers])
    marker_line = MARKER_TEMPLATE.format(marker_str)

    # Add markers after imports
    imports_end = 0
    for match in re.finditer(r"^(?:import|from).*?$", content, re.MULTILINE):
        imports_end = match.end()

    if imports_end > 0:
        content = content[: imports_end + 1] + marker_line + content[imports_end + 1 :]
    else:
        # If no imports found, add after pytest import
        pytest_import = content.find("import pytest")
        if pytest_import >= 0:
            end_of_line = content.find("\n", pytest_import)
            content = (
                content[: end_of_line + 1] + marker_line + content[end_of_line + 1 :]
            )
        else:
            # Otherwise, add after docstring
            module_header_end = re.search(r'("""|\'\'\').*?\1\s*', content, re.DOTALL)
            if module_header_end:
                insert_position = module_header_end.end()
                content = (
                    content[:insert_position] + marker_line + content[insert_position:]
                )
            else:
                # Last resort, add to the beginning
                content = marker_line + content

    # Write the updated content back
    with open(file_path, "w") as f:
        f.write(content)

    print(f"Added markers {markers} to {file_path}")
    return True


def main():
    """Main function to add markers to all test files."""
    base_dir = Path("tests")

    # Get all Python test files
    test_files = list(base_dir.glob("**/test_*.py"))

    # Add markers to each file
    success_count = 0
    for file_path in test_files:
        if add_markers_to_file(file_path):
            success_count += 1

    print(f"\nAdded markers to {success_count} of {len(test_files)} test files")


if __name__ == "__main__":
    main()
