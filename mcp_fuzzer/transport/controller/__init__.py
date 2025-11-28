"""Transport controllers for driver coordination and process supervision."""

__all__ = [
    "TransportCoordinator",
    "ProcessSupervisor",
    "ProcessState",
]


def __getattr__(name: str):
    if name == "TransportCoordinator":
        from .coordinator import TransportCoordinator

        return TransportCoordinator
    if name == "ProcessSupervisor":
        from .process_supervisor import ProcessSupervisor

        return ProcessSupervisor
    if name == "ProcessState":
        from .process_supervisor import ProcessState

        return ProcessState
    raise AttributeError(f"module {__name__} has no attribute {name}")
