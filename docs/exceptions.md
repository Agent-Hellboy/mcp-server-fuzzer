# Exception Handling

MCP Fuzzer provides a comprehensive exception hierarchy to help diagnose and handle errors that may occur during fuzzing operations. This document outlines the different exception types and provides guidance on how to handle them.

## Exception Hierarchy

All exceptions in MCP Fuzzer inherit from the base `MCPError` class, which itself inherits from Python's built-in `Exception` class.

```
Exception
└── MCPError
    ├── TransportError
    │   ├── ConnectionError
    │   ├── ResponseError
    │   └── AuthenticationError
    ├── MCPTimeoutError
    │   ├── ProcessTimeoutError
    │   └── RequestTimeoutError
    ├── SafetyViolationError
    │   ├── NetworkPolicyViolation
    │   ├── SystemCommandViolation
    │   └── FileSystemViolation
    ├── ServerError
    │   ├── ServerUnavailableError
    │   └── ProtocolError
    ├── ConfigurationError
    │   ├── ConfigFileError
    │   └── ValidationError
    └── FuzzingError
        ├── StrategyError
        └── ExecutorError
```

## Exception Categories

### Transport-related Exceptions

- **TransportError**: Base class for errors related to transport communication
  - **ConnectionError**: Raised when a connection to the server cannot be established
  - **ResponseError**: Raised when the server response cannot be parsed
  - **AuthenticationError**: Raised when authentication with the server fails

### Timeout-related Exceptions

- **MCPTimeoutError**: Base class for timeout errors
  - **ProcessTimeoutError**: Raised when a subprocess execution times out
  - **RequestTimeoutError**: Raised when a network request times out

### Safety-related Exceptions

- **SafetyViolationError**: Base class for safety policy violations
  - **NetworkPolicyViolation**: Raised when a network policy is violated
  - **SystemCommandViolation**: Raised when a system command violates safety rules
  - **FileSystemViolation**: Raised when a file system operation violates safety rules

### Server-related Exceptions

- **ServerError**: Base class for server-side errors
  - **ServerUnavailableError**: Raised when the server is unavailable
  - **ProtocolError**: Raised when the server protocol is incompatible

### Configuration-related Exceptions

- **ConfigurationError**: Base class for configuration errors
  - **ConfigFileError**: Raised for errors related to configuration files
  - **ValidationError**: Raised when configuration validation fails

### Fuzzing-related Exceptions

- **FuzzingError**: Base class for errors during fuzzing operations
  - **StrategyError**: Raised when a fuzzing strategy encounters an error
  - **ExecutorError**: Raised when the async executor encounters an error

## Handling Exceptions

### Best Practices

1. **Catch Specific Exceptions**: Always catch the most specific exception type that applies to your situation
2. **Log Exception Details**: Include exception details in logs for easier debugging
3. **Graceful Degradation**: When possible, handle exceptions gracefully and continue operation
4. **User Feedback**: Provide clear, actionable feedback to users when errors occur

### Example: Transport Error Handling

```python
from mcp_fuzzer.exceptions import ConnectionError, ResponseError, AuthenticationError

try:
    # Attempt to communicate with the server
    result = transport.send_request(data)
except ConnectionError as e:
    logging.error(f"Failed to connect to server: {e}")
    # Handle connection failure
except ResponseError as e:
    logging.error(f"Invalid response from server: {e}")
    # Handle response parsing failure
except AuthenticationError as e:
    logging.error(f"Authentication failed: {e}")
    # Handle authentication failure
```

### Example: Safety Violation Handling

```python
from mcp_fuzzer.exceptions import NetworkPolicyViolation, SystemCommandViolation

try:
    # Attempt an operation that might violate safety policies
    result = safety_system.check_operation(operation)
except NetworkPolicyViolation as e:
    logging.warning(f"Network policy violation: {e}")
    # Handle network policy violation
except SystemCommandViolation as e:
    logging.warning(f"System command violation: {e}")
    # Handle system command violation
```

## Adding Custom Exceptions

You can extend the exception hierarchy by creating your own exception classes:

```python
from mcp_fuzzer.exceptions import MCPError

class CustomError(MCPError):
    """Custom error for specific scenarios."""
    pass
```

## Exception Propagation

MCP Fuzzer is designed to propagate exceptions up the call stack until they are handled. This allows you to catch exceptions at the appropriate level of abstraction.

For example, a `NetworkPolicyViolation` raised by the safety system will propagate up through the transport layer, the fuzzer, and eventually to your application code, where you can handle it appropriately.
