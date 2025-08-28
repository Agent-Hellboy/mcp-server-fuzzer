"""Custom exceptions for MCP Fuzzer to standardize error handling."""


class MCPError(Exception):
    """Base exception class for MCP Fuzzer errors."""

    pass


class TransportError(MCPError):
    """Raised for errors related to transport communication."""

    pass


class MCPTimeoutError(MCPError):
    """Raised when an operation times out."""

    pass


class SafetyViolationError(MCPError):
    """Raised when a safety policy is violated."""

    pass


class ServerError(MCPError):
    """Raised for server-side errors during communication."""

    pass


class ConfigurationError(MCPError):
    """Raised for configuration-related errors."""

    pass
