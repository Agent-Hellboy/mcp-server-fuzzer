"""Custom exceptions for MCP Fuzzer to standardize error handling."""


class MCPError(Exception):
    """Base exception class for MCP Fuzzer errors."""

    pass


# Transport-related exceptions
class TransportError(MCPError):
    """Raised for errors related to transport communication."""

    pass


class ConnectionError(TransportError):
    """Raised when a connection to the server cannot be established."""

    pass


class ResponseError(TransportError):
    """Raised when the server response cannot be parsed."""

    pass


class AuthenticationError(TransportError):
    """Raised when authentication with the server fails."""

    pass


# Timeout-related exceptions
class MCPTimeoutError(MCPError):
    """Raised when an operation times out."""

    pass


class ProcessTimeoutError(MCPTimeoutError):
    """Raised when a subprocess execution times out."""

    pass


class RequestTimeoutError(MCPTimeoutError):
    """Raised when a network request times out."""

    pass


# Safety-related exceptions
class SafetyViolationError(MCPError):
    """Raised when a safety policy is violated."""

    pass


class NetworkPolicyViolation(SafetyViolationError):
    """Raised when a network policy is violated."""

    pass


class SystemCommandViolation(SafetyViolationError):
    """Raised when a system command violates safety rules."""

    pass


class FileSystemViolation(SafetyViolationError):
    """Raised when a file system operation violates safety rules."""

    pass


# Server-related exceptions
class ServerError(MCPError):
    """Raised for server-side errors during communication."""

    pass


class ServerUnavailableError(ServerError):
    """Raised when the server is unavailable."""

    pass


class ProtocolError(ServerError):
    """Raised when the server protocol is incompatible."""

    pass


# Configuration-related exceptions
class ConfigurationError(MCPError):
    """Raised for configuration-related errors."""

    pass


class ConfigFileError(ConfigurationError):
    """Raised for errors related to configuration files."""

    pass


class ValidationError(ConfigurationError):
    """Raised when configuration validation fails."""

    pass


# Fuzzing-related exceptions
class FuzzingError(MCPError):
    """Raised for errors during fuzzing operations."""

    pass


class StrategyError(FuzzingError):
    """Raised when a fuzzing strategy encounters an error."""

    pass


class ExecutorError(FuzzingError):
    """Raised when the async executor encounters an error."""

    pass
