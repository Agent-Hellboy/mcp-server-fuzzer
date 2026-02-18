# MCP Server Fuzzer Tests

This directory contains tests for the MCP Server Fuzzer project. The tests are organized by component to make it easier to run specific tests and maintain the test suite.

## Test Structure

The test directory is organized as follows:

```
tests/
├── unit/                     # Unit tests for individual components
│   ├── auth/                 # Tests for authentication components
│   ├── cli/                  # Tests for CLI components
│   ├── client/               # Tests for client components
│   ├── config/               # Tests for configuration components
│   ├── fuzz_engine/          # Tests for fuzzing engine components
│   │   ├── fuzzer/           # Tests for fuzzer implementations
│   │   ├── runtime/          # Tests for runtime components
│   │   └── strategy/         # Tests for fuzzing strategies
│   ├── safety_system/        # Tests for safety system components
│   └── transport/            # Tests for transport components
├── integration/              # Integration tests across components
└── conftest.py               # Pytest configuration and helpers
```

## Running Tests

You can run tests in different ways:

### Run all tests

```bash
pytest
# or
tox -e tests
```

### Run container smoke test (distroless image)

```bash
# Ensure the image exists first (docker build -t mcp-fuzzer:latest .)
tests/e2e/test_healthcheck_container.sh
```

### Run tests for specific components

```bash
# Run all tests for the auth component
pytest -xvs tests/unit/auth

# Run tests by marker
pytest -xvs -m auth

# Run tests for multiple components
pytest -xvs -m "auth or transport"

# Run only integration tests
pytest -xvs -m integration
```

### Run tests for components with changes

You can run tests only for components that have changes in Git:

```bash
# Run tests for components that have changes
pytest --changed-only
```

### Using tox with component selection

```bash
# Run tests for specific components
tox -e tests -- -m auth

# Run tests for changed components
tox -e tests -- --changed-only
```

## Adding New Tests

When adding new tests:

1. Place the test in the appropriate component directory
2. Ensure the test file name follows the `test_*.py` pattern
3. Run `tests/add_markers.py` to automatically add component markers
4. Add pytest markers for components the test covers

Example:

```python
#!/usr/bin/env python3
"""
Test description
"""

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.auth]

# Test code goes here
```

## Integration Tests

Integration tests verify that components work correctly together. These tests should be placed in the `integration/` directory and marked with the `integration` marker.

Integration tests typically:
- Test the interaction between two or more components
- Test end-to-end functionality
- May use real or simulated external services
