# MCP Server Fuzzer

Black-box security assessment for live
[Model Context Protocol](https://modelcontextprotocol.io/) servers. It drives an
authorized target over its real transport, sends realistic and malformed input,
classifies the responses, and writes findings and reproduction data to disk.

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/tests.yml)
[![Lint](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![Codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)
[![MCP versions](https://img.shields.io/badge/MCP-2024--11--05%20%7C%202025--03--26%20%7C%202025--06--18%20%7C%202025--11--25%20%7C%202026--07--28-0f766e)](https://modelcontextprotocol.io/specification/2026-07-28/)
[![Docker pulls](https://img.shields.io/docker/pulls/princekrroshan01/mcp-fuzzer)](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab)](https://www.python.org/downloads/)

**[Documentation](https://agent-hellboy.github.io/mcp-server-fuzzer/)** |
**[Assessment workflow](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/audit-workflow/)** |
**[CLI reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)** |
**[Releases](https://github.com/Agent-Hellboy/mcp-server-fuzzer/releases)**

## Authorization

Use this tool only against MCP servers you own or are explicitly authorized to
test. It sends attack-pattern input, can start local processes, and with
`--auth-audit-intrusive` will register OAuth clients on the target's
authorization server. The built-in safety controls reduce accidental impact;
they are not a substitute for a container, a VM, or an engagement-specific
network boundary. `--security-audit-intrusive` sends a foreign-Origin probe to
test DNS-rebinding defenses and requires the same explicit authorization.

## What it does

The fuzzer connects over stdio, HTTP, SSE, or Streamable HTTP and answers a
fixed set of assessment questions:

- What tools, resources, prompts, and protocol methods does the server expose?
- Does it reject malformed and out-of-contract input, or accept it?
- Do tool descriptions or schemas carry poisoning markers, hidden instructions,
  duplicate definitions, typosquatted names, or dangerous capability
  combinations?
- Does an advertised OAuth boundary publish unsafe metadata or serve tools
  without the expected authentication?
- What does a local stdio server execute, read, write, or connect to while the
  test runs?

## Install

Requires Python 3.10 or newer.

```bash
python -m pip install mcp-fuzzer
mcp-fuzzer --version
```

Optional runtime observation of local stdio processes:

```bash
python -m pip install "mcp-fuzzer[mcpfz-probe]"
```

Docker image
([princekrroshan01/mcp-fuzzer](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer)):

```bash
docker pull princekrroshan01/mcp-fuzzer:latest
docker run --rm princekrroshan01/mcp-fuzzer:latest --help
```

## Run an assessment

Against a remote HTTP or Streamable HTTP target:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint https://target.example.com/mcp \
  --phase realistic \
  --runs 10 \
  --security-audit \
  --seed 42 \
  --output-dir reports/baseline
```

Against a local stdio target, confine file operations and deny non-local
network access:

```bash
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --runs 5 \
  --seed 42 \
  --output-dir reports/baseline
```

To try the tool without a target, use the bundled fixtures in
[`examples/`](examples/).

Start with low run counts, bounded timeouts, dedicated credentials, and an
isolated target. The
[assessment workflow](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/audit-workflow/)
describes what to record at each stage.

## What it produces

Every session writes to `--output-dir` (default `reports/`):

| Artifact | Contents |
| --- | --- |
| `findings.json` | Every finding, with `category`, `severity`, `kind`, `target`, `run`, `detail`, and an `evidence` object |
| `run_summary.json` | Mode, status, tool discovery result, per-tool run counts and outcome buckets, finding totals by category |
| `sessions/<session-id>/<timestamp>_fuzzing_results.json` | Per-run request and response records for the session |
| `crashes/` | One JSON repro per run that terminated the server process, containing the input and crash context. Written only when a run crashes the target |

Severities are `critical`, `high`, `medium`, `low`, and `info`. Fuzz
classifications include `accepted_malformed`, `injection_reflection`, `crash`,
`hang`, `error_leakage`, `internal_error`, `non_determinism`, `memory_growth`,
`oversized_response`, and `performance_outlier`.

A finding from `--security-audit` carries a stable check ID and maps to
published sources:

```json
{
  "category": "tool_poisoning",
  "severity": "high",
  "kind": "tool",
  "target": "read_notes",
  "detail": "Tool name or description contains injection/poisoning markers (hidden instructions or secret-path references).",
  "evidence": {
    "check_id": "TP1",
    "paper_arxiv_id": "2503.23278",
    "owasp_mcp_top_10": "MCP03:2025",
    "markers": ["ignore\\s+(all\\s+)?previous\\s+instructions?", "id_rsa"],
    "tool_definition_hash": "18cd91e6…"
  }
}
```

`--export-csv`, `--export-xml`, `--export-html`, and `--export-markdown` write
additional per-run tables into the same directory. These exports carry a
metadata block (session ID, mode, protocol, endpoint, timestamps) and per-run
pass/fail rows. They do not carry severities or findings, and only the CSV
export includes the arguments that produced each run. Treat `findings.json` as
the authoritative output.

Exit codes: `0` success, `1` validation or execution failure, `2` no tools
discovered with `--fail-if-no-tools`, `130` interrupted.

## What it does not do

- It does not read your source. This is a black-box client, not a SAST tool.
- It does not prove exploitability. `accepted_malformed` means the server
  returned a non-error response to schema-invalid or attack-pattern input. That
  is a contract observation and a lead, not a demonstrated vulnerability.
- It does not record the seed in any output file. `--seed` makes payload
  generation reproducible, but you must record the value yourself alongside the
  report for a run to be replayable.
- It does not record the endpoint or protocol in `run_summary.json`. That
  metadata appears only in the CSV, XML, HTML, and Markdown exports.
- It does not assign CVEs, CVSS scores, or remediation guidance, and it is not
  a certification.
- It does not test authorization logic between users or tenants. The auth
  checks cover metadata, the authorization endpoint, and unauthenticated tool
  exposure.
- It only reaches what the server advertises through `tools/list`,
  `resources/list`, and `prompts/list`. Undiscoverable surface is not tested.
- Schema-driven fuzzing via `--spec-schema-version` reads MCP schemas from the
  `schemas/mcp-spec` submodule, which is not shipped in the PyPI package. From a
  released install, point `MCP_SPEC_SCHEMA_ROOT` at a schema directory or work
  from a git checkout.

## Audit surfaces

`--security-audit` runs tool and schema checks plus active output oracles
against the same run's results: poisoning markers, hidden or encoded
instructions, tool shadowing, typosquatted names, dangerous capability
combinations, cleartext transport, and command, path, SQL, and prompt-injection
oracles. Add `--security-audit-intrusive` to probe whether an HTTP/SSE target
rejects a foreign `Origin`. Every MCP revision requires servers to validate
`Origin`; revisions from `2025-11-25` onward additionally mandate HTTP 403 for
an invalid one, so the finding wording is scoped to the negotiated revision.
The probe replays configured transport authentication, and a probe still
refused with HTTP 401 is reported as inconclusive rather than clean.

`--auth-audit` runs read-only OAuth checks against an HTTP or SSE endpoint:
metadata review, authorization-endpoint probes, and unauthenticated tool
exposure where authentication is advertised. Add `--auth-audit-intrusive` only
when your authorization explicitly covers dynamic client registration and
redirect handling.

`--runtime-probe` observes process, filesystem, network, credential, privilege,
and ptrace activity for a local stdio target. The `mcpfz-probe` sidecar is
optional, disabled by default, and fails open if it cannot observe the target.

## Handling evidence

Reports embed generated arguments, server responses, paths, and runtime
observations. Values under credential-named keys (`token`, `secret`,
`authorization`, `api_key`, and similar) are redacted in console output and in
written artifacts, and credentials embedded in URLs are stripped. Redaction is
key-driven, so a secret echoed inside a response body under an unrelated key is
not caught. Review and redact artifacts before sharing them, and store them
under the same restrictions as the engagement's other evidence. See
[understand run results](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/results/).

## Documentation

- [Choose an assessment path](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/)
- [Run the assessment workflow](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/audit-workflow/)
- [Focused audit recipes](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/examples/)
- [Interpret evidence and findings](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/results/)
- [Configure repeatable assessments](https://agent-hellboy.github.io/mcp-server-fuzzer/configuration/configuration/)
- [Contain local targets](https://agent-hellboy.github.io/mcp-server-fuzzer/components/safety/)
- [Collect evidence in CI](https://agent-hellboy.github.io/mcp-server-fuzzer/security-ci/)
- [CLI reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)

## References

The checks in this project complement, and do not replace, the
[MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices),
the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
and the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

## License

MIT. See [LICENSE](LICENSE).
