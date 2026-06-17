"""MCP spec checks - prompt list and get checks."""

from typing import Any

from .check_ids import CheckID
from .helpers import (
    PROMPTS_SPEC,
    SpecCheck,
    fail as _fail,
    warn as _warn,
)

_PROMPTS_SPEC = PROMPTS_SPEC

def check_prompts_list(result: Any) -> list[SpecCheck]:
    """Validate prompts/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    prompts = result.get("prompts")
    if prompts is None:
        checks.append(
            _fail(CheckID.PROMPTS_LIST_MISSING, "Missing prompts array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(prompts, list):
        checks.append(
            _fail(
                CheckID.PROMPTS_LIST_TYPE, "prompts is not an array", _PROMPTS_SPEC
            )
        )
        return checks

    for idx, prompt in enumerate(prompts):
        if not isinstance(prompt, dict):
            checks.append(
                _fail(
                    CheckID.PROMPTS_LIST_ITEM,
                    f"Prompt {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not prompt.get("name"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_LIST_NAME,
                    f"Prompt {idx} missing name",
                    _PROMPTS_SPEC,
                )
            )
    return checks


def check_prompts_get(result: Any) -> list[SpecCheck]:
    """Validate prompts/get response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    messages = result.get("messages")
    if messages is None:
        checks.append(
            _fail(CheckID.PROMPTS_GET_MISSING, "Missing messages array", _PROMPTS_SPEC)
        )
        return checks

    if not isinstance(messages, list):
        checks.append(
            _fail(
                CheckID.PROMPTS_GET_TYPE, "messages is not an array", _PROMPTS_SPEC
            )
        )
        return checks

    if not messages:
        checks.append(
            _warn(
                CheckID.PROMPTS_GET_EMPTY, "messages array is empty", _PROMPTS_SPEC
            )
        )
        return checks

    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_ITEM,
                    f"Message {idx} is not an object",
                    _PROMPTS_SPEC,
                )
            )
            continue
        if not message.get("role"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_ROLE,
                    f"Message {idx} missing role",
                    _PROMPTS_SPEC,
                )
            )
        if not message.get("content"):
            checks.append(
                _fail(
                    CheckID.PROMPTS_GET_CONTENT,
                    f"Message {idx} missing content",
                    _PROMPTS_SPEC,
                )
            )

    return checks
