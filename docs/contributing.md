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

## Development Setup

### Prerequisites

- Python 3.9 or higher

- Git
- pip or conda for package management

### Local Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mcp-server-fuzzer.git
cd mcp-server-fuzzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Verify setup
mcp-fuzzer --help
```

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

The test suite includes built-in safety measures:

```python
# Safety check - prevent dangerous tests on production systems
def is_safe_test_environment():
    """Check if we're in a safe environment for running potentially dangerous tests."""
    # Don't run dangerous tests on production systems
    if (os.getenv("CI") or
        os.getenv("PRODUCTION") or
        os.getenv("DANGEROUS_TESTS_DISABLED")):
        return False

    # Don't run on systems with critical processes
    try:
        with open("/proc/1/comm", "r") as f:
            init_process = f.read().strip()
            if init_process in ["systemd", "init"]:
                return False
    except (OSError, IOError):
        pass

    return True

# Skip dangerous tests if not in safe environment
SAFE_ENV = is_safe_test_environment()

# Add safety decorator for dangerous tests
def safe_test_only(func):
    """Decorator to skip dangerous tests on production systems."""
    def wrapper(*args, **kwargs):
        if not SAFE_ENV:
            pytest.skip("Dangerous test skipped on production system")
        return func(*args, **kwargs)
    return wrapper
```

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

- **Line Length**: Maximum 88 characters (Black default)

- **Imports**: Use absolute imports, group by standard library, third-party, local

- **Type Hints**: Use type hints for all function parameters and return values

- **Documentation**: Include docstrings for all public functions and classes

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
├── index.md              # Home page
├── getting-started.md    # Installation and basic usage
├── architecture.md       # System design and components
├── examples.md           # Working examples and configurations
├── reference.md          # Complete API reference
├── safety.md             # Safety system configuration
└── contributing.md       # This file
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

To add new safety features:

1. **Extend SafetySystem class**
2. **Implement safety logic**
3. **Add configuration options**
4. **Write tests**
5. **Update documentation**

## 🐛 Bug Reports

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

- Python Version: [e.g., 3.9.7]
- MCP Fuzzer Version: [e.g., 0.1.0]

## Error Messages
Any error messages or stack traces

## Additional Information
Any other relevant information
```

## 💡 Feature Requests

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

- **MINOR**: New functionality (backward compatible)

- **PATCH**: Bug fixes (backward compatible)

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

## 🙏 Acknowledgments

Thank you to all contributors who have helped make MCP Server Fuzzer better:

- **Code Contributors**: Everyone who has submitted PRs

- **Bug Reporters**: Users who report issues

- **Documentation Contributors**: Those who improve docs

- **Testers**: Users who test and validate functionality

Your contributions help make this tool more robust, secure, and useful for the MCP community!

---

**Ready to contribute?** Start by forking the repository and checking out the issues labeled "good first issue" or "help wanted"!
