#!/usr/bin/env python3
"""
Unit tests for base Mutator interface.
"""

import pytest

from mcp_fuzzer.fuzz_engine.mutators.base import Mutator

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


def test_mutator_is_abstract():
    """Test that Mutator is an abstract base class."""
    with pytest.raises(TypeError):
        Mutator()


def test_mutator_has_mutate_method():
    """Test that Mutator defines the mutate method."""
    assert hasattr(Mutator, "mutate")
    assert Mutator.mutate.__isabstractmethod__
