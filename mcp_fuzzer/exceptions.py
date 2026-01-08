"""Custom exceptions for MCP Fuzzer to standardize error handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar


@dataclass(frozen=True)
class ErrorMetadata:
    """Structured representation of an MCP error for downstream reporting."""

    code: str
    description: str
    message: str
    context: dict[str, Any]


class MCPError(Exception):
    """Base exception class for MCP Fuzzer errors with standardized codes."""

    code: ClassVar[str] = "MCP-000"
    description: ClassVar[str] = "Generic MCP error"

    def __init__(
        self,
        message: str | None = None,
        reason: str | None = None,
        *,
        code: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        self.context = context or {}
        self.code = code or self.code
        super().__init__(message or reason or "")

    def to_metadata(self) -> ErrorMetadata:
        """Return structured metadata for logging or serialized output."""
        return ErrorMetadata(
            code=self.code,
            description=self.description,
            message=str(self),
            context=self.context,
        )


# Transport-related exceptions -------------------------------------------------
class TransportError(MCPError):
    """Raised for errors related to transport communication."""

    code = "10001"
    description = "Transport failure"


class ConnectionError(TransportError):
    """Raised when a connection to the server cannot be established."""

    code = "10002"
    description = "Unable to establish connection with the server"


class ResponseError(TransportError):
    """Raised when the server response cannot be parsed."""

    code = "10003"
    description = "Malformed or unexpected server response"


class AuthenticationError(TransportError):
    """Raised when authentication with the server fails."""

    code = "10004"
    description = "Authentication with the server failed"


class NetworkError(TransportError):
    """Raised for network policy or connectivity failures."""

    code = "10005"
    description = "Network connectivity or policy failure"


class PayloadValidationError(TransportError):
    """Raised when a JSON-RPC payload is invalid or cannot be serialized."""

    code = "10006"
    description = "Invalid transport payload"


class TransportRegistrationError(TransportError):
    """Raised when transport registration or selection fails."""

    code = "10007"
    description = "Transport registration or selection error"


# Authentication subsystem exceptions -----------------------------------------
class AuthError(MCPError):
    """Base class for authentication subsystem errors."""

    code = "20001"
    description = "Authentication subsystem error"


class AuthConfigError(AuthError):
    """Raised for invalid authentication configuration."""

    code = "20002"
    description = "Authentication configuration is invalid"


class AuthProviderError(AuthError):
    """Raised when an auth provider definition is invalid."""

    code = "20003"
    description = "Authentication provider is misconfigured"


# Timeout-related exceptions ---------------------------------------------------
class MCPTimeoutError(MCPError):
    """Raised when an operation times out."""

    code = "30001"
    description = "Operation timed out"


class ProcessTimeoutError(MCPTimeoutError):
    """Raised when a subprocess execution times out."""

    code = "30002"
    description = "Subprocess execution timed out"


class RequestTimeoutError(MCPTimeoutError):
    """Raised when a network request times out."""

    code = "30003"
    description = "Network request timed out"


# Runtime-related exceptions ---------------------------------------------------
class RuntimeSubsystemError(MCPError):
    """Raised for errors in the runtime management subsystem."""

    code = "95001"
    description = "Runtime management error"


class ProcessStartError(RuntimeSubsystemError):
    """Raised when a managed process fails to start."""

    code = "95002"
    description = "Failed to start managed process"


class ProcessStopError(RuntimeSubsystemError):
    """Raised when a managed process fails to stop."""

    code = "95003"
    description = "Failed to stop managed process"


class ProcessSignalError(RuntimeSubsystemError):
    """Raised when sending a signal to a managed process fails."""

    code = "95004"
    description = "Failed to send process signal"


class ProcessRegistrationError(RuntimeSubsystemError):
    """Raised when registering/unregistering processes with the watchdog fails."""

    code = "95005"
    description = "Process registration failed"


class WatchdogStartError(RuntimeSubsystemError):
    """Raised when the process watchdog cannot be started."""

    code = "95006"
    description = "Process watchdog failed to start"


# Safety-related exceptions ----------------------------------------------------
class SafetyViolationError(MCPError):
    """Raised when a safety policy is violated."""

    code = "40001"
    description = "Safety policy violated"


class NetworkPolicyViolation(SafetyViolationError):
    """Raised when a network policy is violated."""

    code = "40002"
    description = "Network access blocked by safety policy"


class SystemCommandViolation(SafetyViolationError):
    """Raised when a system command violates safety rules."""

    code = "40003"
    description = "System command blocked by safety policy"


class FileSystemViolation(SafetyViolationError):
    """Raised when a file system operation violates safety rules."""

    code = "40004"
    description = "Filesystem access blocked by safety policy"


# Server-related exceptions ----------------------------------------------------
class ServerError(MCPError):
    """Raised for server-side errors during communication."""

    code = "50001"
    description = "Server returned an error"


class ServerUnavailableError(ServerError):
    """Raised when the server is unavailable."""

    code = "50002"
    description = "Server is unavailable or not responding"


class ProtocolError(ServerError):
    """Raised when the server protocol is incompatible."""

    code = "50003"
    description = "Protocol negotiation failed"


# CLI-related exceptions -------------------------------------------------------
class CLIError(MCPError):
    """Raised for errors encountered while parsing or running CLI commands."""

    code = "60001"
    description = "CLI error"


class ArgumentValidationError(CLIError):
    """Raised when CLI arguments are invalid or conflicting."""

    code = "60002"
    description = "Invalid CLI arguments"


# Reporting-related exceptions -------------------------------------------------
class ReportError(MCPError):
    """Raised for reporting/output subsystem errors."""

    code = "70001"
    description = "Reporting error"


class ReportValidationError(ReportError):
    """Raised when report/output data fails validation."""

    code = "70002"
    description = "Report validation failed"


# Configuration-related exceptions ---------------------------------------------
class ConfigurationError(MCPError):
    """Raised for configuration-related errors."""

    code = "80001"
    description = "Configuration error"


class ConfigFileError(ConfigurationError):
    """Raised for errors related to configuration files."""

    code = "80002"
    description = "Configuration file could not be read"


class ValidationError(ConfigurationError):
    """Raised when configuration validation fails."""

    code = "80003"
    description = "Configuration validation failed"


# Fuzzing-related exceptions ---------------------------------------------------
class FuzzingError(MCPError):
    """Raised for errors during fuzzing operations."""

    code = "90001"
    description = "Fuzzing engine error"


class StrategyError(FuzzingError):
    """Raised when a fuzzing strategy encounters an error."""

    code = "90002"
    description = "Fuzzing strategy failed"


class ExecutorError(FuzzingError):
    """Raised when the async executor encounters an error."""

    code = "90003"
    description = "Async executor encountered an error"


def get_error_registry() -> dict[str, str]:
    """Return a mapping of error codes to descriptions for diagnostics."""
    registry: dict[str, str] = {}
    for obj in list(globals().values()):
        if (
            isinstance(obj, type)
            and issubclass(obj, MCPError)
            and hasattr(obj, "code")
            and obj.code not in registry
        ):
            registry[obj.code] = getattr(obj, "description", MCPError.description)
    return dict(sorted(registry.items()))
