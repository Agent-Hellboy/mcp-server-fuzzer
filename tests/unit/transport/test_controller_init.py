#!/usr/bin/env python3
"""
Unit tests for transport.controller module attribute access.
"""

import pytest

import mcp_fuzzer.transport.controller as controller


@pytest.mark.parametrize(
    ("attr", "expected"),
    [
        ("TransportCoordinator", "TransportCoordinator"),
        ("ProcessSupervisor", "ProcessSupervisor"),
        ("ProcessState", "ProcessState"),
    ],
)
def test_controller_getattr_known_symbols(attr, expected):
    cls = getattr(controller, attr)

    assert cls.__name__ == expected


def test_controller_getattr_unknown():
    with pytest.raises(AttributeError):
        getattr(controller, "NotAThing")
