"""Tool metadata and poisoning checks for MCP server audit."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from collections import Counter
from typing import Any

from .model import Finding
from .server import (
    CAPABILITY_COMBO_PAPER_ARXIV_ID,
    TRANSPORT_PAPER_ARXIV_ID,
    server_finding,
)

_POISONING_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"<\s*IMPORTANT\s*>",
        r"<\s*CRITICAL\s*>",
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"do\s+not\s+tell\s+the\s+user",
        r"disregard\s+(prior|previous)",
        r"override\s+(the\s+)?(system|developer|user)\s+(prompt|message)",
        r"reveal\s+(the\s+)?(system|developer)\s+(prompt|message)",
        r"hidden\s+parameter",
        r"secretly\s+(call|use|invoke|run)",
        r"\b(exfiltrate|steal|leak)\b",
        r"(send|upload|post)\s+.*\b(secret|credential|token|private\s+key|api\s+key)\b",
    )
]

_SECRET_PATH_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"\.aws/credentials",
        r"\.env\b",
        r"\.ssh/",
        r"id_rsa",
        r"/etc/passwd",
        r"private\s+key",
        r"bearer\s+token",
    )
]

_INVISIBLE_TEXT_PATTERNS = [
    re.compile(r, re.IGNORECASE | re.DOTALL)
    for r in (
        r"<!--.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?-->",
        r"/\*.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?\*/",
        r"```.*?(ignore\s+(all\s+)?previous|do\s+not\s+tell|secretly\s+call).*?```",
    )
]

_UNICODE_CONTROL_PATTERN = re.compile(
    "[\u001b\u009b\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]"
)
_ANSI_ESCAPE_PATTERN = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
)
_TRIGGER_CONDITIONING_PATTERN = re.compile(
    r"\b(trigger\s+(word|phrase)|when\s+the\s+user\s+says|"
    r"if\s+the\s+user\s+(asks|mentions|requests)|conversation\s+history|"
    r"previous\s+(message|conversation|turn))\b",
    re.IGNORECASE,
)
_BASE64_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])"
)
_MAX_HIDDEN_CARRIER_TEXT_CHARS = 20_000
_MAX_SCHEMA_TEXT_NODES = 10_000
_MAX_SCHEMA_TEXT_DEPTH = 100
_MAX_TOOL_HASH_NODES = 10_000
_MAX_TOOL_HASH_DEPTH = 100
_MAX_TOOL_HASH_STRING_CHARS = 8_192
_MAX_BASE64_CANDIDATES = 32
_MAX_BASE64_CANDIDATE_CHARS = 8_192

_LOCAL_READ_PATTERN = re.compile(
    r"\b(read|file|fs|cat|open|load|path|directory|glob|scan|filesystem)\b",
    re.IGNORECASE,
)
_NETWORK_EGRESS_PATTERN = re.compile(
    r"\b(http|fetch|request|curl|wget|post|url|webhook|upload|send|"
    r"egress|socket|download|api_call)\b",
    re.IGNORECASE,
)

_COMMON_TOOL_NAMES = frozenset(
    {
        "read_file",
        "write_file",
        "delete_file",
        "list_files",
        "run_command",
        "execute_command",
        "search",
        "fetch",
        "get",
        "post",
        "shell",
        "filesystem",
        "sql_query",
        "web_search",
        "browser_search",
        "github_search",
        "github_get_file",
        "github_create_issue",
        "github_list_repositories",
    }
)
_CONFUSABLES = str.maketrans(
    {
        "а": "a",  # Cyrillic
        "е": "e",
        "і": "i",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        # Greek. Keys must be lower-case: ``_name_skeleton`` case-folds before
        # it translates, so upper-case keys would never match.
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "ο": "o",
        "ρ": "p",
        "χ": "x",
        "υ": "y",
    }
)


def _name_skeleton(name: str) -> str:
    """Normalize common Unicode lookalikes before comparing tool names."""
    return unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLES)


def _spelling_form(name: str) -> str:
    """Case-fold a name while preserving compatibility-character evidence.

    NFC is deliberate: NFKC would fold full-width and other compatibility
    forms into their ASCII equivalents, hiding exactly the confusable
    spellings this comparison exists to detect.
    """
    return unicodedata.normalize("NFC", name).casefold()


def _levenshtein_distance(left: str, right: str) -> int:
    """Return edit distance without importing a fuzzy-matching dependency."""
    if len(left) > len(right):
        left, right = right, left
    previous = list(range(len(left) + 1))
    for right_index, right_char in enumerate(right, start=1):
        current = [right_index]
        for left_index, left_char in enumerate(left, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[left_index] + 1,
                    previous[left_index - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]


def _tool_name_squatting_match(name: str) -> dict[str, Any] | None:
    """Return evidence when a name closely imitates a common tool name."""
    skeleton = _name_skeleton(name)
    spelling = _spelling_form(name)
    for known_name in _COMMON_TOOL_NAMES:
        if skeleton == known_name and spelling != known_name:
            return {
                "matched_name": known_name,
                "match_type": "unicode_confusable",
            }
        distance = _levenshtein_distance(skeleton, known_name)
        threshold = 1 if max(len(skeleton), len(known_name)) < 6 else 2
        if distance <= threshold and skeleton != known_name:
            return {
                "matched_name": known_name,
                "match_type": "edit_distance",
                "edit_distance": distance,
            }
    return None


def _tool_definition_hash(tool: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    stack: list[tuple[tuple[str, ...], Any, int]] = [((), tool, 0)]
    visited_nodes = 0

    def update(*parts: object) -> None:
        digest.update("\t".join(str(part) for part in parts).encode("utf-8"))
        digest.update(b"\n")

    while stack:
        if visited_nodes >= _MAX_TOOL_HASH_NODES:
            update("<truncated>", len(stack))
            break

        path, obj, depth = stack.pop()
        visited_nodes += 1
        path_text = ".".join(path)
        if depth > _MAX_TOOL_HASH_DEPTH:
            update(path_text, "<max_depth>")
            continue

        if isinstance(obj, dict):
            update(path_text, "dict", len(obj))
            for key in sorted(obj.keys(), key=str, reverse=True):
                if visited_nodes + len(stack) >= _MAX_TOOL_HASH_NODES:
                    update(path_text, "<max_nodes>")
                    break
                key_text = str(key)
                stack.append((path + (key_text,), obj[key], depth + 1))
        elif isinstance(obj, list):
            update(path_text, "list", len(obj))
            for idx in range(len(obj) - 1, -1, -1):
                if visited_nodes + len(stack) >= _MAX_TOOL_HASH_NODES:
                    update(path_text, "<max_nodes>")
                    break
                stack.append((path + (str(idx),), obj[idx], depth + 1))
        elif isinstance(obj, str):
            update(path_text, "str", obj[:_MAX_TOOL_HASH_STRING_CHARS])
        else:
            update(
                path_text,
                type(obj).__name__,
                repr(obj)[:_MAX_TOOL_HASH_STRING_CHARS],
            )

    return digest.hexdigest()


def _tool_text(
    tool: dict[str, Any], *, max_chars: int | None = None
) -> str:
    parts: list[str] = []
    remaining = max_chars

    def append_text(text: str) -> None:
        nonlocal remaining
        if remaining is None:
            parts.append(text)
            return
        if remaining <= 0:
            return
        chunk = text[:remaining]
        parts.append(chunk)
        remaining -= len(chunk)

    append_text(str(tool.get("name") or ""))
    if tool.get("description"):
        append_text(str(tool["description"]))
    if tool.get("title"):
        append_text(str(tool["title"]))
    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        parts.append(_collect_schema_text(annotations, max_chars=remaining))
    return "\n".join(parts)


def _collect_schema_text(
    value: Any, *, max_chars: int | None = None
) -> str:
    parts: list[str] = []
    remaining = max_chars
    visited_nodes = 0

    def append_text(text: str) -> None:
        nonlocal remaining
        if remaining is None:
            parts.append(text)
            return
        if remaining <= 0:
            return
        chunk = text[:remaining]
        parts.append(chunk)
        remaining -= len(chunk)

    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        if visited_nodes >= _MAX_SCHEMA_TEXT_NODES:
            break
        if remaining is not None and remaining <= 0:
            break

        obj, depth = stack.pop()
        visited_nodes += 1
        if depth > _MAX_SCHEMA_TEXT_DEPTH:
            continue

        if isinstance(obj, dict):
            for key, val in obj.items():
                if visited_nodes + len(stack) >= _MAX_SCHEMA_TEXT_NODES:
                    break
                stack.append((val, depth + 1))
                if isinstance(key, str):
                    stack.append((key, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                if visited_nodes + len(stack) >= _MAX_SCHEMA_TEXT_NODES:
                    break
                stack.append((item, depth + 1))
        elif isinstance(obj, str):
            append_text(obj)

    return "\n".join(parts)


def _matched_markers(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    return [p.pattern for p in patterns if p.search(text)]


def _scan_poisoning(text: str) -> list[str]:
    hits = _matched_markers(text, _POISONING_PATTERNS)
    hits.extend(_matched_markers(text, _SECRET_PATH_PATTERNS))
    return hits


def _decode_base64_candidate(candidate: str) -> str | None:
    padded = candidate + ("=" * (-len(candidate) % 4))
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    if printable / max(len(text), 1) < 0.85:
        return None
    return text


def _scan_hidden_instruction_carriers(text: str) -> list[dict[str, Any]]:
    text = text[:_MAX_HIDDEN_CARRIER_TEXT_CHARS]
    hits: list[dict[str, Any]] = []
    if _ANSI_ESCAPE_PATTERN.search(text):
        hits.append({"kind": "ansi_escape"})
    elif _UNICODE_CONTROL_PATTERN.search(text):
        hits.append({"kind": "unicode_control"})
    for pattern in _INVISIBLE_TEXT_PATTERNS:
        if pattern.search(text):
            hits.append({"kind": "hidden_comment", "pattern": pattern.pattern})
    for candidate_count, match in enumerate(_BASE64_CANDIDATE_PATTERN.finditer(text)):
        if candidate_count >= _MAX_BASE64_CANDIDATES:
            break
        candidate = match.group(0)[:_MAX_BASE64_CANDIDATE_CHARS]
        decoded = _decode_base64_candidate(candidate)
        if not decoded:
            continue
        decoded_hits = _scan_poisoning(decoded)
        if decoded_hits:
            hits.append(
                {
                    "kind": "encoded_payload",
                    "encoding": "base64",
                    "markers": decoded_hits[:10],
                }
            )
    return hits


def audit_tool_metadata(tools: list[dict[str, Any]]) -> list[Finding]:
    """Scan ``tools/list`` definitions for poisoning, shadowing, and exfil chains."""
    findings: list[Finding] = []
    if not tools:
        return findings

    names: list[str] = []
    definition_hashes_by_name: dict[str, set[str]] = {}
    local_read_tools: set[str] = set()
    network_egress_tools: set[str] = set()

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        tool_hash = _tool_definition_hash(tool)
        if isinstance(name, str) and name:
            names.append(name)
            definition_hashes_by_name.setdefault(name, set()).add(tool_hash)

        visible = _tool_text(tool, max_chars=_MAX_HIDDEN_CARRIER_TEXT_CHARS)
        if _LOCAL_READ_PATTERN.search(visible):
            if name:
                local_read_tools.add(str(name))
        if _NETWORK_EGRESS_PATTERN.search(visible):
            if name:
                network_egress_tools.add(str(name))

        poison_hits = _scan_poisoning(visible)
        if poison_hits and name:
            findings.append(
                server_finding(
                    "TP1",
                    "tool_poisoning",
                    "high",
                    str(name),
                    "Tool name or description contains injection/poisoning "
                    "markers (hidden instructions or secret-path references).",
                    evidence={
                        "markers": poison_hits[:10],
                        "tool_definition_hash": tool_hash,
                    },
                )
            )
        if isinstance(name, str) and name:
            squatting = _tool_name_squatting_match(name)
            if squatting:
                findings.append(
                    server_finding(
                        "NS1",
                        "tool_name_squatting",
                        "low",
                        name,
                        "Tool name closely imitates a common tool name; "
                        "review it for typosquatting or shadow-tool risk.",
                        arxiv_id=TRANSPORT_PAPER_ARXIV_ID,
                        evidence={
                            **squatting,
                            "tool_definition_hash": tool_hash,
                        },
                    )
                )
        hidden_hits = _scan_hidden_instruction_carriers(visible)
        if hidden_hits and name:
            findings.append(
                server_finding(
                    "HI1",
                    "hidden_instruction",
                    "high",
                    str(name),
                    "Tool metadata contains hidden or encoded instruction "
                    "carriers (invisible Unicode, hidden comments, or encoded "
                    "prompt-injection payloads).",
                    evidence={
                        "carriers": hidden_hits[:10],
                        "tool_definition_hash": tool_hash,
                    },
                )
            )
        if _TRIGGER_CONDITIONING_PATTERN.search(visible) and name:
            findings.append(
                server_finding(
                    "TC1",
                    "tool_conditioning",
                    "medium",
                    str(name),
                    "Tool metadata conditions behavior on trigger phrases or "
                    "conversation history, which can hide context-dependent "
                    "tool behavior from review.",
                    evidence={"tool_definition_hash": tool_hash},
                )
            )

        schema = tool.get("inputSchema")
        if isinstance(schema, dict):
            schema_text = _collect_schema_text(
                schema, max_chars=_MAX_HIDDEN_CARRIER_TEXT_CHARS
            )
            schema_hits = _scan_poisoning(schema_text)
            if schema_hits and name:
                findings.append(
                    server_finding(
                        "SP1",
                        "schema_poisoning",
                        "high",
                        str(name),
                        "Tool inputSchema text contains injection/poisoning "
                        "markers beyond the visible tool signature.",
                        evidence={
                            "markers": schema_hits[:10],
                            "tool_definition_hash": tool_hash,
                        },
                    )
                )
            hidden_schema_hits = _scan_hidden_instruction_carriers(schema_text)
            if hidden_schema_hits and name:
                findings.append(
                    server_finding(
                        "HI2",
                        "hidden_instruction",
                        "high",
                        str(name),
                        "Tool inputSchema contains hidden or encoded instruction "
                        "carriers.",
                        evidence={
                            "carriers": hidden_schema_hits[:10],
                            "tool_definition_hash": tool_hash,
                        },
                    )
                )

    name_counts = Counter(names)
    dupes = [n for n, count in name_counts.items() if count > 1]
    for dupe in dupes:
        findings.append(
            server_finding(
                "TS1",
                "tool_shadowing",
                "medium",
                dupe,
                f"Duplicate tool name '{dupe}' appears {name_counts[dupe]} times "
                "(tool shadowing / name collision within this server).",
                evidence={"occurrences": name_counts[dupe]},
            )
        )
        hashes = sorted(definition_hashes_by_name.get(dupe, set()))
        if len(hashes) > 1:
            findings.append(
                server_finding(
                    "TD1",
                    "tool_definition_drift",
                    "high",
                    dupe,
                    f"Duplicate tool name '{dupe}' has divergent definitions "
                    "(possible in-session rug pull or shadowing).",
                    evidence={"definition_hashes": hashes},
                )
            )

    if local_read_tools and network_egress_tools:
        findings.append(
            server_finding(
                "CC1",
                "dangerous_capability_combo",
                "medium",
                "mcp_endpoint",
                "Server exposes both local-read and network-egress style tools "
                "(parasitic toolchain / data-exfiltration chain risk).",
                arxiv_id=CAPABILITY_COMBO_PAPER_ARXIV_ID,
                evidence={
                    "local_read_tools": sorted(local_read_tools),
                    "network_egress_tools": sorted(network_egress_tools),
                },
            )
        )

    return findings
