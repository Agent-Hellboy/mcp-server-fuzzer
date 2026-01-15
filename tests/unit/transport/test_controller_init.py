#!/usr/bin/env python3
"""
Unit tests for transport.controller module attribute access.
"""

import pytest

import mcp_fuzzer.transport.controller as controller


def test_controller_getattr_transport_coordinator():
    cls = getattr(controller, "TransportCoordinator")

    assert cls.__name__ == "TransportCoordinator"


def test_controller_getattr_process_supervisor():
    cls = getattr(controller, "ProcessSupervisor")

    assert cls.__name__ == "ProcessSupervisor"


def test_controller_getattr_process_state():
    cls = getattr(controller, "ProcessState")

    assert cls.__name__ == "ProcessState"


def test_controller_getattr_unknown():
    with pytest.raises(AttributeError):
        getattr(controller, "NotAThing")
