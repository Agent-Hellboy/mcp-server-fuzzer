import random

from mcp_fuzzer.fuzz_engine.mutators.context import FuzzerContext, ensure_context


def test_with_defaults_sets_rng_and_run_index():
    rng = random.Random(0)
    ctx = FuzzerContext(rng=rng)

    normalized = ctx.with_defaults()

    assert normalized.rng is rng
    assert normalized.run_index == 885440


def test_ensure_context_builds_defaults():
    rng = random.Random(1)

    ctx = ensure_context(
        None,
        phase="realistic",
        rng=rng,
    )

    assert ctx.phase == "realistic"
    assert ctx.havoc_mode is False
    assert ctx.havoc_min == 2
    assert ctx.havoc_max == 6
    assert ctx.run_index == 140891


def test_ensure_context_overrides_existing():
    rng = random.Random(2)
    base = FuzzerContext(
        phase="aggressive",
        schema={"field": "value"},
        key="old",
        run_index=5,
        rng=rng,
        havoc_mode=False,
    )

    ctx = ensure_context(
        base,
        phase="realistic",
        key="new",
        havoc_mode=True,
    )

    assert ctx.phase == "realistic"
    assert ctx.key == "new"
    assert ctx.schema == {"field": "value"}
    assert ctx.havoc_mode is True
    assert ctx.run_index == 5
