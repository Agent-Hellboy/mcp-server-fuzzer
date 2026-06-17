"""MCP spec checks - resource list, read, template, and subscription checks."""

from typing import Any

from .check_ids import CheckID
from .helpers import (
    RESOURCES_SPEC,
    SpecCheck,
    fail as _fail,
    warn as _warn,
)

_RESOURCES_SPEC = RESOURCES_SPEC

def check_resources_list(result: Any) -> list[SpecCheck]:
    """Validate resources/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    resources = result.get("resources")
    if resources is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_LIST_MISSING,
                "Missing resources array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(resources, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_LIST_TYPE,
                "resources is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, resource in enumerate(resources):
        if not isinstance(resource, dict):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_ITEM,
                    f"Resource {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not resource.get("uri"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_URI,
                    f"Resource {idx} missing uri",
                    _RESOURCES_SPEC,
                )
            )
        if not resource.get("name"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_LIST_NAME,
                    f"Resource {idx} missing name",
                    _RESOURCES_SPEC,
                )
            )

    return checks


def check_resources_read(result: Any) -> list[SpecCheck]:
    """Validate resources/read response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    contents = result.get("contents")
    if contents is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_READ_MISSING,
                "Missing contents array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(contents, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_READ_TYPE,
                "contents is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not contents:
        checks.append(
            _warn(
                CheckID.RESOURCES_READ_EMPTY,
                "contents array is empty",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, item in enumerate(contents):
        if isinstance(item, dict):
            if not item.get("uri"):
                checks.append(
                    _fail(
                        CheckID.RESOURCES_READ_URI,
                        f"Content {idx} missing uri",
                        _RESOURCES_SPEC,
                    )
                )
            if not (item.get("text") or item.get("blob")):
                checks.append(
                    _fail(
                        CheckID.RESOURCES_READ_BODY,
                        f"Content {idx} missing text or blob",
                        _RESOURCES_SPEC,
                    )
                )
        else:
            checks.append(
                _fail(
                    CheckID.RESOURCES_READ_ITEM,
                    f"Content {idx} is not object",
                    _RESOURCES_SPEC,
                )
            )

    return checks


def check_resource_templates_list(result: Any) -> list[SpecCheck]:
    """Validate resources/templates/list response shape."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        return checks

    templates = result.get("resourceTemplates")
    if templates is None:
        checks.append(
            _fail(
                CheckID.RESOURCES_TEMPLATES_MISSING,
                "Missing resourceTemplates array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    if not isinstance(templates, list):
        checks.append(
            _fail(
                CheckID.RESOURCES_TEMPLATES_TYPE,
                "resourceTemplates is not an array",
                _RESOURCES_SPEC,
            )
        )
        return checks

    for idx, template in enumerate(templates):
        if not isinstance(template, dict):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_ITEM,
                    f"Template {idx} is not an object",
                    _RESOURCES_SPEC,
                )
            )
            continue
        if not template.get("uriTemplate"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_URI,
                    f"Template {idx} missing uriTemplate",
                    _RESOURCES_SPEC,
                )
            )
        if not template.get("name"):
            checks.append(
                _fail(
                    CheckID.RESOURCES_TEMPLATES_NAME,
                    f"Template {idx} missing name",
                    _RESOURCES_SPEC,
                )
            )

    return checks
def check_subscribe_result(result: Any) -> list[SpecCheck]:
    """Validate resources/subscribe response shape (must be EmptyResult {})."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        checks.append(
            _fail(
                CheckID.SUBSCRIBE_RESULT_TYPE,
                "resources/subscribe result is not an object",
                _RESOURCES_SPEC,
            )
        )
    return checks


def check_unsubscribe_result(result: Any) -> list[SpecCheck]:
    """Validate resources/unsubscribe response shape (must be EmptyResult {})."""
    checks: list[SpecCheck] = []
    if not isinstance(result, dict):
        checks.append(
            _fail(
                CheckID.UNSUBSCRIBE_RESULT_TYPE,
                "resources/unsubscribe result is not an object",
                _RESOURCES_SPEC,
            )
        )
    return checks
def check_resources_updated_notification(payload: dict[str, Any]) -> list[SpecCheck]:
    """Validate notifications/resources/updated payload shape."""
    checks: list[SpecCheck] = []
    params = payload.get("params")
    if not isinstance(params, dict):
        checks.append(
            _fail(
                CheckID.RESOURCES_UPDATED_PARAMS_TYPE,
                "notifications/resources/updated params is not an object",
                _RESOURCES_SPEC,
            )
        )
        return checks

    uri = params.get("uri")
    if not isinstance(uri, str) or not uri:
        checks.append(
            _fail(
                CheckID.RESOURCES_UPDATED_URI_MISSING,
                "notifications/resources/updated missing uri",
                _RESOURCES_SPEC,
            )
        )

    return checks
