# Getting Started

This guide takes you from installation to a repeatable MCP fuzzing session.

## Install

### PyPI

```bash
python -m pip install mcp-fuzzer
mcp-fuzzer --help
```

### Docker

```bash
docker pull princekrroshan01/mcp-fuzzer:latest
docker run --rm princekrroshan01/mcp-fuzzer:latest --help
```

For a source checkout:

```bash
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
python -m pip install -e .
```

## Choose a target

The endpoint format depends on the transport:

| Transport | Endpoint example |
| --- | --- |
| HTTP or HTTPS | https://localhost:8000/mcp |
| SSE | http://localhost:8000/sse |
| Streamable HTTP | http://localhost:8000/mcp |
| stdio | python my_server.py |

The bundled examples provide local targets for HTTP, Streamable HTTP, Go stdio, and TypeScript stdio testing.

## Run a first session

For an HTTP or Streamable HTTP server:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint http://localhost:8000/mcp \
  --runs 10 \
  --output-dir reports
```

For a local stdio server:

```bash
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --runs 5 \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --output-dir reports
```

Use --phase realistic for valid-input coverage, --phase aggressive for edge and attack-oriented inputs, or --phase both for both passes. Use --mode protocol to fuzz protocol messages and --protocol-type to select one message type.

## Add security checks

Tool and output security checks run after the fuzz session:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol https \
  --endpoint https://example.test/mcp \
  --security-audit \
  --auth-audit \
  --runs 10 \
  --output-dir reports
```

Use --auth-audit-intrusive only against a server you are authorized to test. It may exercise dynamic registration and redirect validation.

For CI and registry checks, use --fail-if-no-tools so an unreachable or protected target is not mistaken for a clean run.

## Review the output

A completed run creates:

- findings.json: security and reliability findings.
- run_summary.json: completion status, counts, and target metadata.
- crashes/: available crash reproductions and server output.
- Optional exports from --export-csv, --export-xml, --export-html, and --export-markdown.

Each finding includes a category, severity, target, run identifier, evidence, and source references. Findings mapped to the OWASP MCP Top 10 include a link in the evidence.

## Select an MCP version

The default is 2025-11-25. Available schema-driven versions are 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and 2026-07-28.

```bash
mcp-fuzzer \
  --mode protocol \
  --protocol streamablehttp \
  --endpoint http://localhost:8000/mcp \
  --spec-schema-version 2026-07-28 \
  --runs-per-type 5
```

The version can also be set in YAML or with MCP_SPEC_SCHEMA_VERSION. See [Configuration](../configuration/configuration.md).

## Enable runtime monitoring

Runtime monitoring is an optional companion feature for stdio targets:

```bash
python -m pip install "mcp-fuzzer[mcpfz-probe]"
```

Install the sidecar binary using the [mcpfz-probe release instructions](https://github.com/Agent-Hellboy/mcpfz-probe/releases), verify its published checksum, then run:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --runtime-probe \
  --runtime-probe-backend auto \
  --runtime-probe-bin /path/to/mcpfz-probe \
  --runs 3 \
  --output-dir reports
```

Use fake for portable tests and auto for capability-aware selection. eBPF requires Linux support and appropriate privileges. The monitor is disabled unless requested and fails open if it cannot start or observe an event.

## Next steps

- [Examples](examples.md)
- [Configuration](../configuration/configuration.md)
- [Safety and isolation](../components/safety.md)
- [CLI reference](../development/reference.md)
- [Security CI guidance](../SECURITY_CI.md)
