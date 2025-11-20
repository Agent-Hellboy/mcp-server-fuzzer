"""Output subsystem for standardized report artifacts."""

from .protocol import OutputProtocol
from .manager import OutputManager

__all__ = ["OutputProtocol", "OutputManager"]
