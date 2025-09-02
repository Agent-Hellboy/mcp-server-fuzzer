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
    "unit/fuzz_engine/fuzzer": ["unit", "fuzz_engine", "fuzzer"],
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
    for path_prefix, path_markers in COMPONENT_MARKERS.items():
        if parent_dir.startswith(path_prefix):
            markers = path_markers
            break

    if not markers:
        print(f"Could not determine markers for {file_path}")
        return False

    # Read the file content
    with open(file_path, "r") as f:
        content = f.read()

    # Check if markers already exist
    if "pytestmark =" in content:
        print(f"Markers already exist in {file_path}")
        return True

    # Add pytest import if needed
    if "import pytest" not in content:
        # Find the end of the imports or docstring
        module_header_end = re.search(r'""".*?"""\s*', content, re.DOTALL)
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
            module_header_end = re.search(r'""".*?"""\s*', content, re.DOTALL)
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
