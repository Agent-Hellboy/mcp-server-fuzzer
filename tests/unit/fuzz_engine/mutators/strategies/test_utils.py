from mcp_fuzzer.fuzz_engine.mutators.strategies.utils import (
    ConstraintMode,
    fit_to_constraints,
)


def test_fit_to_constraints_enforce_pad_and_trim():
    assert fit_to_constraints("a", min_length=3) == "aaa"
    assert fit_to_constraints("abcdef", max_length=3) == "abc"


def test_fit_to_constraints_truncate_no_padding():
    assert (
        fit_to_constraints("a", min_length=3, mode=ConstraintMode.TRUNCATE) == "a"
    )


def test_fit_to_constraints_violate_max_and_min():
    assert (
        fit_to_constraints("abc", max_length=2, mode=ConstraintMode.VIOLATE)
        == "abca"
    )
    assert (
        fit_to_constraints("abcdef", min_length=3, mode=ConstraintMode.VIOLATE)
        == "ab"
    )


def test_fit_to_constraints_handles_zero_max():
    assert fit_to_constraints("abc", max_length=0) == ""
    assert fit_to_constraints("abc", max_length=-1) == ""
