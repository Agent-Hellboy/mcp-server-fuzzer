# Contributing

Thank you for your interest in contributing to MCP Server Fuzzer! This guide will help you get started with development and contribution.

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Reports** - Report issues and bugs

- **Feature Requests** - Suggest new features and improvements

- **Code Contributions** - Submit pull requests with code changes

- **Documentation** - Improve documentation and examples

- **Testing** - Help test and validate functionality

- **Security** - Report security vulnerabilities

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** for your changes
4. **Make your changes** with proper testing
5. **Submit a pull request** with clear description

### Understanding the Design Patterns

Before diving into code contributions, we highly recommend reviewing our [Design Pattern Review](../design-pattern-review.md) document. This comprehensive guide is especially valuable for:

**Beginners:**
- Learn how design patterns are applied in real-world projects
- Understand the purpose of each module and its patterns
- See practical examples of Factory, Strategy, Observer, and other patterns

**Intermediate Developers:**
- Review pattern fit scores and understand architectural decisions
- Identify areas for improvement and contribution opportunities
- Learn about cross-cutting concerns and modularity observations

**What the document covers:**
- Module-by-module pattern analysis with fit scores (0-10)
- Commentary on what works well and what could be improved
- Complete pattern map for every module in the codebase
- Suggested next steps for refactoring and improvements

**Key sections to review based on your contribution area:**
- Contributing to CLI → Review "CLI Layer" section
- Adding transports → Review "Transport Layer" section
- Improving runtime → Review "Runtime & Process Management" section
- Enhancing safety → Review "Safety System" section

This understanding will help you:
- Write code that fits the existing architecture
- Identify the right place for new features
- Understand why certain design decisions were made
- Propose improvements that align with the project's goals

## Development Setup

### Prerequisites

- Python 3.10 or higher

- Git
- pip or conda for package management

### Local Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-server-fuzzer.git
cd mcp-server-fuzzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify setup
mcp-fuzzer --help
```

> A project-wide `requirements.txt` is included for quick bootstrapping.
> After activating your virtual environment you can also run
> `pip install -r requirements.txt` to pull in every dependency the docs and
> examples rely on.

### Interactive Code Exploration

Once the dependencies are installed, open an interactive session with
`python3 -i` from the project root and paste the snippet below. It gives you a
peek into how the client wires transports and tool fuzzers together without
having to run the entire CLI:

```python
import asyncio
from mcp_fuzzer.transport import create_transport
from mcp_fuzzer.client import MCPFuzzerClient


async def explore_client():
    transport = create_transport("http", "http://localhost:8000", timeout=5.0)
    client = MCPFuzzerClient(transport=transport, safety_enabled=False)
    print(f"Initialized {transport.__class__.__name__} at {transport.url}")
    print(
        "Tool fuzzer concurrency:",
        client.tool_client.tool_fuzzer.executor.max_concurrency,
    )
    await client.cleanup()


asyncio.run(explore_client())
```

Feel free to swap in any endpoint that matches your local MCP server to inspect
the objects that back the CLI.

> Need to poke at coroutines without writing helper scripts? Python ships an
> asyncio-aware REPL: run `python3 -m asyncio` and you get a prompt that accepts
> top-level `await`. Paste the snippet above, drop the final `asyncio.run(...)`,
> and simply type `await explore_client()` to drive the coroutine directly.

### Development Dependencies

The project includes development dependencies in `pyproject.toml`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-asyncio>=0.21.0",
    "ruff>=0.1.0",
    "black>=23.0.0",
    "mypy>=1.0.0",
    "pre-commit>=3.5.0",
    "tox>=4.0.0"
]
docs = [
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.0.0",
    "mkdocs-minify-plugin>=0.7.0"
]
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_fuzzer --cov-report=html

# Run specific test modules
pytest tests/test_transport.py
pytest tests/test_cli.py

#Run Individual test
pytest tests/test_transport.py::TestTransportProtocol.test_get_tools_success

# Run with verbose output
pytest -v -s

# Run tests in parallel
pytest -n auto
```

### Test Safety Features

End-to-end tests often spawn local MCP servers and can trigger external
processes. Use the same safety features that the CLI exposes when running tests
manually:

- Set `MCP_FUZZER_SAFETY_ENABLED=true` (or pass `--enable-safety-system` to CLI
  invocations inside tests) so argument filtering stays active.
- Provide a dedicated sandbox directory via `MCP_FUZZER_FS_ROOT` or `--fs-root`
  to contain any files created by tools under test.
- When you intentionally disable safety (for example, to fuzz filesystem-heavy
  tools), run inside a disposable VM or container. There is no automatic
  environment detection, so treat these flags as the final line of defense.

### Test Coverage

```bash
# Generate coverage report
pytest --cov=mcp_fuzzer --cov-report=html

# View coverage report
open htmlcov/index.html  # On macOS
xdg-open htmlcov/index.html  # On Linux
start htmlcov/index.html  # On Windows
```

## Code Quality

### Linting and Formatting

```bash
# Run linting with ruff
ruff check mcp_fuzzer tests

# Fix linting issues automatically
ruff check --fix mcp_fuzzer tests

# Format code with black
black mcp_fuzzer tests

# Type checking with mypy
mypy mcp_fuzzer
```

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.0.270
    hooks:
      - id: ruff
        args: [--fix]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

### Code Style Guidelines

- **Python**: Follow PEP 8 style guide

- **Line Length**: Maximum 88 characters (enforced by Ruff)
  - Break long lines across multiple statements
  - Use implicit line continuation for function signatures and strings
  - Avoid f-strings without placeholders

- **F-strings**: Always include placeholders when using f-strings
  - Use regular strings for static messages
  - Extract complex expressions to variables if needed

- **Imports**: Use absolute imports, group by standard library, third-party, local

- **Type Hints**: Use type hints for all function parameters and return values

- **Documentation**: Include docstrings for all public functions and classes

- **Logging**: Use appropriate logging levels
  - DEBUG: Tool call notifications and detailed execution flow
  - INFO: Important state changes and user-facing information
  - WARNING: Potential issues that don't prevent execution
  - ERROR: Errors that require attention

## Documentation

### Building Documentation

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Build documentation
mkdocs build

# Serve documentation locally
mkdocs serve

# Build and deploy to GitHub Pages
mkdocs gh-deploy
```

### Documentation Standards

- **Markdown**: Use Markdown for all documentation

- **Code Examples**: Include working code examples

- **API Reference**: Document all public APIs

- **Diagrams**: Use Mermaid for architecture diagrams

- **Links**: Use relative links within the documentation

### Documentation Structure

```
docs/
| -- index.md              # Home page
| -- getting-started.md    # Installation and basic usage
| -- architecture.md       # System design and components
| -- examples.md           # Working examples and configurations
| -- reference.md          # Complete API reference
| -- safety.md             # Safety system configuration
| -- contributing.md       # This file
```

## Adding New Features

### Transport Protocols

To add a new transport protocol:

1. **Create transport class** in `mcp_fuzzer/transport/`
2. **Implement TransportProtocol interface**
3. **Add to transport factory**
4. **Write comprehensive tests**
5. **Update documentation**

```python
# Example: Custom Transport Protocol
from mcp_fuzzer.transport import TransportProtocol

class CustomTransport(TransportProtocol):
    def __init__(self, endpoint: str, **kwargs):
        self.endpoint = endpoint
        self.config = kwargs

    async def send_request(self, method: str, params=None):
        # Your implementation
        pass

    async def send_raw(self, payload):
        # Your implementation
        pass

    async def send_notification(self, method: str, params=None):
        # Your implementation
        pass
```

### Fuzzing Strategies

To add new fuzzing strategies:

1. **Create strategy class** in appropriate directory
2. **Implement strategy interface**
3. **Add to strategy manager**
4. **Write tests**
5. **Update documentation**

```python
# Example: Custom Fuzzing Strategy
class CustomToolStrategy:
    def generate_test_data(self, tool_schema: Dict[str, Any]) -> Dict[str, Any]:
        # Your data generation logic
        return {"custom_param": "custom_value"}
```

### Safety Features

To introduce new safety capabilities:

1. **Extend or wrap `SafetyFilter`** (for argument-level filtering) or add helpers
   under `safety_system/blocking`, `detection`, or `filesystem` as appropriate.
2. **Expose configuration hooks** (CLI flags or config file entries) when needed.
3. **Write unit tests** covering the new patterns, shims, or sandbox behaviors.
4. **Document the feature** so operators understand the new protections.

## Working with Internal APIs

This section provides code examples for working with internal components of MCP Server Fuzzer. These are useful when extending the fuzzer or building custom tooling.

You can save all those code snippet as test.py and run it as `python -i test.py`
and debug objects inside the repl

### Process Management

The `ProcessManager` provides robust process lifecycle management with watchdog monitoring.

#### Basic Process Management

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime import WatchdogConfig

async def basic_process_management():
    # Configure watchdog
    watchdog_config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=30.0,
        auto_kill=True
    )

    # Create process manager
    manager = ProcessManager.from_config(watchdog_config)

    try:
        # Start a test server
        config = ProcessConfig(
            command=["python", "test_server.py"],
            name="test_server",
            timeout=60.0
        )
        process = await manager.start_process(config)

        # Monitor process
        status = await manager.get_process_status(process.pid)
        print(f"Process {process.pid} status: {status['status']}")

        # Let it run for a while
        await asyncio.sleep(10)

        # Stop gracefully
        await manager.stop_process(process.pid)

    finally:
        await manager.shutdown()

if __name__ == "__main__":
    asyncio.run(basic_process_management())
```

#### Process with Activity Monitoring

```python
import time

async def process_with_activity_monitoring():
    manager = ProcessManager.from_config()

    # Activity callback for hang detection
    last_activity = time.time()

    def activity_callback():
        nonlocal last_activity
        return last_activity

    def update_activity():
        nonlocal last_activity
        last_activity = time.time()

    config = ProcessConfig(
        command=["python", "long_running_server.py"],
        name="long_server",
        activity_callback=activity_callback,
        timeout=120.0
    )

    process = await manager.start_process(config)

    try:
        # Simulate periodic activity updates
        for i in range(20):
            update_activity()
            await manager.update_activity(process.pid)
            await asyncio.sleep(2)

    finally:
        await manager.stop_process(process.pid)
        await manager.shutdown()
```

#### Multiple Process Management

```python
async def multiple_process_management():
    manager = ProcessManager.from_config()

    try:
        # Start multiple worker processes
        processes = []
        for i in range(3):
            config = ProcessConfig(
                command=["python", f"worker_{i}.py"],
                name=f"worker_{i}",
                timeout=30.0
            )
            process = await manager.start_process(config)
            processes.append(process)

        # Monitor all processes
        all_processes = await manager.list_processes()
        print(f"Managing {len(all_processes)} processes")

        # Get statistics
        stats = await manager.get_stats()
        print(f"Process statistics: {stats}")

        # Wait for all processes to complete
        await asyncio.sleep(30)

    finally:
        # Stop all processes
        await manager.stop_all_processes()
        await manager.shutdown()
```

### AsyncFuzzExecutor

The `AsyncFuzzExecutor` provides concurrency control for fuzzing operations.

#### Basic Executor Usage

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def basic_executor_usage():
    executor = AsyncFuzzExecutor(max_concurrency=3)

    try:
        # Execute batch operations
        async def sample_operation(value):
            await asyncio.sleep(0.5)
            return f"processed_{value}"

        # Prepare operations as (function, args, kwargs) tuples
        operations = [
            (sample_operation, [i], {}) for i in range(10)
        ]

        # Execute batch with concurrency control
        results = await executor.execute_batch(operations)
        
        print(f"Successful results: {len(results['results'])}")
        print(f"Errors: {len(results['errors'])}")
        
        for result in results['results']:
            print(f"Result: {result}")

    finally:
        await executor.shutdown()
```

#### Batch Operations with Error Handling

```python
async def batch_operations_example():
    executor = AsyncFuzzExecutor(max_concurrency=5)

    try:
        # Define multiple operations (some will fail)
        async def operation(x):
            await asyncio.sleep(0.1)
            if x % 3 == 0:  # Some operations fail
                raise Exception(f"Operation {x} failed")
            return f"result_{x}"

        # Prepare operations list
        operations = [(operation, [i], {}) for i in range(10)]

        # Execute batch - automatically collects results and errors
        results = await executor.execute_batch(operations)

        print(f"Successful results: {len(results['results'])}")
        print(f"Errors: {len(results['errors'])}")

        # Process successful results
        for result in results['results']:
            print(f"Success: {result}")

        # Handle errors
        for error in results['errors']:
            print(f"Error: {error}")

    finally:
        await executor.shutdown()
```

#### Custom Concurrency Configuration

```python
async def custom_executor_configuration():
    # High concurrency for I/O-bound operations
    io_executor = AsyncFuzzExecutor(max_concurrency=20)

    # Low concurrency for CPU-bound operations
    cpu_executor = AsyncFuzzExecutor(max_concurrency=4)

    try:
        # I/O-bound operations
        async def io_operation():
            await asyncio.sleep(0.1)  # Simulate I/O
            return "io_result"

        # CPU-bound operations (sync function runs in thread pool)
        def cpu_operation():
            # Simulate CPU work
            return sum(range(1_000_000))

        # Execute with appropriate executor
        io_results = await io_executor.execute_batch([
            (io_operation, [], {}) for _ in range(20)
        ])

        cpu_results = await cpu_executor.execute_batch([
            (cpu_operation, [], {}) for _ in range(4)
        ])

        print(f"IO results: {len(io_results['results'])}")
        print(f"CPU results: {len(cpu_results['results'])}")

    finally:
        await io_executor.shutdown()
        await cpu_executor.shutdown()
```

### Custom Transport Implementation

To create a custom transport protocol:

```python
from mcp_fuzzer.transport import TransportProtocol

class CustomTransport(TransportProtocol):
    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.config = kwargs

    async def send_request(self, method: str, params=None):
        # Your custom implementation
        return {"result": "custom_response"}
```

Using a custom transport:

```python
from mcp_fuzzer.client import MCPFuzzerClient

# Create custom transport
transport = CustomTransport("custom-endpoint")

# Use with fuzzer client (with optional concurrency control)
client = MCPFuzzerClient(
    transport,
    max_concurrency=10  # Optional: Control concurrent operations
)

# Run fuzzing
await client.fuzz_tools(runs=10)
```

### Report Analysis and Processing

#### JSON Report Processing

```python
import json
from datetime import datetime

def analyze_fuzzing_report(report_path):
    with open(report_path, 'r') as f:
        report = json.load(f)

    # Extract metadata
    metadata = report['metadata']
    print(f"Session: {metadata['session_id']}")
    print(f"Mode: {metadata['mode']}")
    start = datetime.fromisoformat(metadata['start_time'])
    end = datetime.fromisoformat(metadata['end_time'])
    print(f"Duration: {end - start}")

    # Analyze tool results
    tool_results = report.get('tool_results', {})
    for tool_name, results in tool_results.items():
        success_count = sum(1 for r in results if r.get('success', False))
        total_count = len(results)
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0

        print(f"Tool {tool_name}: {success_rate:.1f}% success rate")

    # Analyze safety data
    safety_data = report.get('safety_data', {})
    if safety_data:
        blocked_operations = safety_data.get('blocked_operations', [])
        print(f"Blocked operations: {len(blocked_operations)}")

        for operation in blocked_operations[:5]:  # Show first 5
            print(f"  - {operation['operation']}: {operation['reason']}")

# Usage
analyze_fuzzing_report("reports/fuzzing_report_20250812_143000.json")
```

#### Safety Report Analysis

```python
import json

def analyze_safety_report(safety_report_path):
    with open(safety_report_path, 'r') as f:
        safety_report = json.load(f)

    # Analyze blocked operations by type
    blocked_by_type = {}
    for operation in safety_report.get('blocked_operations', []):
        op_type = operation.get('operation_type', 'unknown')
        blocked_by_type[op_type] = blocked_by_type.get(op_type, 0) + 1

    print("Blocked operations by type:")
    for op_type, count in blocked_by_type.items():
        print(f"  {op_type}: {count}")

    # Analyze risk levels
    risk_levels = safety_report.get('risk_assessments', {})
    print("\nRisk level distribution:")
    for level, count in risk_levels.items():
        print(f"  {level}: {count}")

    # Show recent blocked operations
    recent_blocks = safety_report.get('recent_blocks', [])
    print(f"\nRecent blocked operations ({len(recent_blocks)}):")
    for block in recent_blocks[-5:]:  # Last 5
        print(f"  - {block['timestamp']}: {block['operation']}")

# Usage
analyze_safety_report("reports/safety_report_20250812_143000.json")
```

#### Programmatic Report Creation

```python
from pathlib import Path
from mcp_fuzzer.reports.reporter import FuzzerReporter


async def custom_report_generation():
    reporter = FuzzerReporter(
        config_provider={
            "output": {
                "directory": "custom_reports",
                "types": ["fuzzing_results", "safety_summary"],
                "compress": False,
            }
        }
    )

    reporter.set_fuzzing_metadata(
        mode="tools",
        protocol="stdio",
        endpoint="test-endpoint",
        runs=3,
    )

    reporter.add_tool_results(
        "test_tool",
        [
            {"run": 1, "success": True, "args": {"param": "value1"}},
            {"run": 2, "success": False, "exception": "Invalid argument"},
            {"run": 3, "success": True, "args": {"param": "value2"}},
        ],
    )

    reporter.add_protocol_results(
        "InitializeRequest",
        [
            {"run": 1, "success": True},
            {"run": 2, "success": True},
        ],
    )

    reporter.add_safety_data(
        {
            "blocked_operations": [
                {
                    "operation": "file_write",
                    "reason": "Outside sandbox",
                    "timestamp": "2025-08-12T14:30:00",
                }
            ],
            "risk_assessments": {"high": 1, "medium": 0, "low": 0},
        }
    )

    reporter.generate_final_report(include_safety=True)
    reporter.generate_standardized_report(
        output_types=["fuzzing_results", "error_report"], include_safety=True
    )

    print("Custom reports generated in 'custom_reports' directory")
```

#### Report Comparison

```python
import json

def compare_reports(report1_path, report2_path):
    with open(report1_path, 'r') as f:
        report1 = json.load(f)

    with open(report2_path, 'r') as f:
        report2 = json.load(f)

    # Compare success rates
    def get_success_rate(report):
        tool_results = report.get('tool_results', {})
        total_success = 0
        total_runs = 0

        for tool_name, results in tool_results.items():
            success_count = sum(1 for r in results if r.get('success', False))
            total_success += success_count
            total_runs += len(results)

        return (total_success / total_runs * 100.0) if total_runs else 0.0

    rate1 = get_success_rate(report1)
    rate2 = get_success_rate(report2)

    print(f"Report 1 success rate: {rate1:.1f}%")
    print(f"Report 2 success rate: {rate2:.1f}%")
    print(f"Improvement: {rate2 - rate1:.1f} percentage points")

    # Compare safety data
    safety1 = report1.get('safety_data', {}).get('blocked_operations', [])
    safety2 = report2.get('safety_data', {}).get('blocked_operations', [])

    print(f"Report 1 blocked operations: {len(safety1)}")
    print(f"Report 2 blocked operations: {len(safety2)}")

# Usage
compare_reports(
    "reports/fuzzing_report_20250812_143000.json",
    "reports/fuzzing_report_20250812_150000.json"
)
```

## Bug Reports

### Reporting Bugs

When reporting bugs, please include:

1. **Clear description** of the issue
2. **Steps to reproduce** the problem
3. **Expected behavior** vs actual behavior
4. **Environment details** (OS, Python version, etc.)
5. **Error messages** and stack traces
6. **Minimal example** that demonstrates the issue

### Bug Report Template

```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Environment
- OS: [e.g., Ubuntu 20.04]

- Python Version: [e.g., 3.10.17]
- MCP Fuzzer Version: [e.g., 0.1.0]

## Error Messages
Any error messages or stack traces

## Additional Information
Any other relevant information
```

## Feature Requests

### Suggesting Features

When suggesting features, please include:

1. **Clear description** of the feature
2. **Use case** and motivation
3. **Proposed implementation** (if you have ideas)
4. **Alternatives considered**
5. **Impact** on existing functionality

### Feature Request Template

```markdown
## Feature Description
Brief description of the requested feature

## Use Case
Why this feature would be useful

## Proposed Implementation
How you think it could be implemented

## Alternatives
Other approaches you've considered

## Impact
How this would affect existing functionality
```

## Security

### Security Vulnerabilities

If you discover a security vulnerability:

1. **Do not open a public issue**
2. **Email security@example.com** (replace with actual security contact)
3. **Include detailed description** of the vulnerability
4. **Provide steps to reproduce** if possible
5. **Wait for response** before public disclosure

### Security Best Practices

- **Never commit secrets** or sensitive information

- **Use environment variables** for configuration

- **Validate all input** from external sources

- **Follow principle of least privilege**

- **Keep dependencies updated**

## Pull Requests

### PR Guidelines

1. **Create feature branch** from main branch
2. **Make focused changes** - one feature per PR
3. **Write clear commit messages** following conventional commits
4. **Include tests** for new functionality
5. **Update documentation** as needed
6. **Ensure all tests pass**
7. **Request review** from maintainers

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(transport): add WebSocket transport support
fix(cli): resolve argument parsing issue
docs(examples): add authentication examples
test(fuzzer): add test coverage for edge cases
```

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature

- [ ] Documentation update

- [ ] Test addition
- [ ] Other

## Testing
- [ ] All tests pass

- [ ] New tests added for new functionality
- [ ] Documentation updated

## Checklist
- [ ] Code follows style guidelines

- [ ] Self-review completed

- [ ] Documentation updated
- [ ] Tests added/updated
```

## Release Process

### Versioning

The project uses semantic versioning:

- **MAJOR**: Incompatible API changes

- **MINOR**: New functionality that preserves the public API

- **PATCH**: Bug fixes that do not change the API

### Release Steps

1. **Update version** in `pyproject.toml`
2. **Update changelog** with release notes
3. **Create release tag** on GitHub
4. **Build and publish** to PyPI
5. **Update documentation** if needed

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests

- **GitHub Discussions**: General questions and discussions

- **Pull Requests**: Code contributions

- **Email**: Security issues (security@example.com)

### Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please:

- **Be respectful** and inclusive

- **Focus on the code** and technical discussions

- **Help others** learn and grow

- **Report inappropriate behavior** to maintainers

## Resources

### Learning Resources

- **MCP Specification**: [Model Context Protocol](https://github.com/modelcontextprotocol/modelcontextprotocol)

- **Python Testing**: [pytest documentation](https://docs.pytest.org/)

- **Code Quality**: [Ruff documentation](https://docs.astral.sh/ruff/)

- **Documentation**: [MkDocs documentation](https://www.mkdocs.org/)

### Related Projects

- **MCP Python SDK**: [mcp/python-sdk](https://github.com/modelcontextprotocol/python-sdk)

- **MCP Server Examples**: Various MCP server implementations

- **Fuzzing Tools**: AFL, libFuzzer, and other fuzzing frameworks

## Acknowledgments

Thank you to all contributors who have helped make MCP Server Fuzzer better:

- **Code Contributors**: Everyone who has submitted PRs

- **Bug Reporters**: Users who report issues

- **Documentation Contributors**: Those who improve docs

- **Testers**: Users who test and validate functionality

Your contributions help make this tool more robust, secure, and useful for the MCP community.

---

**Ready to contribute?** Start by forking the repository and checking out the issues labeled "good first issue" or "help wanted".
