# Audit recipes and maintained fixtures

These recipes are deliberately small. Copy one, change the target and output
directory, and keep each assessment question in its own report directory.
The repository's maintained local MCP fixtures live under
[`examples/`](https://github.com/Agent-Hellboy/mcp-server-fuzzer/tree/main/examples)
and are useful for validating transports, authentication, stdio containment,
and report handling. They are test fixtures, not security certifications or
compatibility guarantees.

## Recipe: remote baseline

```bash
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint https://target.example/mcp \
  --phase realistic \
  --runs 10 \
  --seed 42 \
  --output-dir reports/baseline
```

Use `--protocol https` for a conventional HTTPS endpoint and `--protocol sse`
for an SSE endpoint. Confirm the endpoint and transport with the server owner.

## Recipe: tool and schema security review

```bash
mcp-fuzzer \
  --mode tools \
  --protocol https \
  --endpoint https://target.example/mcp \
  --phase aggressive \
  --security-audit \
  --runs 20 \
  --seed 42 \
  --output-dir reports/security
```

The audit inspects tool names, descriptions, annotations, schemas, duplicate
definitions, transport configuration, and selected output oracles. Treat
metadata signals as analyst leads: read the exact evidence and verify whether a
client or model would actually consume the content in a dangerous way.

## Recipe: protocol and state behavior

```bash
# Structured protocol behavior
mcp-fuzzer \
  --mode protocol \
  --protocol streamablehttp \
  --endpoint https://target.example/mcp \
  --protocol-phase realistic \
  --runs-per-type 5 \
  --output-dir reports/protocol

# A focused message type
mcp-fuzzer \
  --mode protocol \
  --protocol-type CallToolRequest \
  --protocol streamablehttp \
  --endpoint https://target.example/mcp \
  --protocol-phase aggressive \
  --runs-per-type 10 \
  --output-dir reports/call-tool
```

Add `--stateful` only when the target's behavior depends on sequences. Use
`--spec-schema-version` when comparing a server against a specific MCP schema.

## Recipe: authentication boundary

For a read-only OAuth assessment:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol https \
  --endpoint https://target.example/mcp \
  --auth-audit \
  --security-audit \
  --runs 10 \
  --output-dir reports/auth
```

For authenticated tool calls, prefer a restricted config file or environment
variables over putting secrets directly in shell history. Example auth files
must use placeholders:

```json
{
  "providers": {
    "assessment": {
      "type": "api_key",
      "api_key": "REPLACE_WITH_A_TEST_KEY",
      "header_name": "Authorization",
      "prefix": "Bearer"
    }
  },
  "default_provider": "assessment"
}
```

```bash
mcp-fuzzer \
  --mode tools \
  --protocol https \
  --endpoint https://target.example/mcp \
  --auth-config ./auth_config.json \
  --runs 10 \
  --output-dir reports/authenticated
```

Use `--auth-audit-intrusive` only when dynamic client registration and redirect
validation are explicitly in scope. Keep intrusive results separate from the
read-only baseline.

## Recipe: local stdio containment

```bash
mkdir -p fuzz-sandbox
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --phase aggressive \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --runs 5 \
  --security-audit \
  --output-dir reports/stdio
```

`--fs-root` and the safety system are fuzzer controls, not a full operating
system sandbox. Use a container or VM for untrusted server code.

## Recipe: runtime observation

Runtime observation is for authorized local stdio targets when host behavior is
part of the question:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --runtime-probe \
  --runtime-probe-backend auto \
  --runtime-probe-bin /path/to/mcpfz-probe \
  --runtime-probe-workspace "$PWD/fuzz-sandbox" \
  --runtime-probe-tmpdir /tmp \
  --runtime-probe-allow-exec /usr/bin/date \
  --runtime-probe-allow-host api.example.com \
  --runs 3 \
  --output-dir reports/runtime
```

The sidecar can provide evidence about process execution, network connections,
credential reads, filesystem changes, privilege changes, and ptrace activity.
Review the [runtime monitor setup](getting-started.md#optional-observe-a-local-process)
and [mcpfz-probe documentation](https://github.com/Agent-Hellboy/mcpfz-probe)
for host prerequisites.

## Recipe: maintain a reproducible run

Use a fixed seed, a versioned config, a dedicated output directory, and an
explicit schema version:

```bash
mcp-fuzzer \
  --config assessment.yaml \
  --spec-schema-version 2025-11-25 \
  --seed 42 \
  --output-dir reports/2025-11-25-seed-42
```

Save the command line, config hash, target revision, and tool version with the
assessment record. A seed improves reproduction; it does not guarantee that a
remote target or stateful server is deterministic.

## Maintained local fixtures

From a source checkout, see [`examples/README.md`](https://github.com/Agent-Hellboy/mcp-server-fuzzer/blob/main/examples/README.md)
for commands for:

- the Python HTTP fixture with public and protected tools;
- the Streamable HTTP fixture;
- Go and TypeScript stdio fixtures;
- authentication configuration and transport checks.

Use these fixtures to verify that a local installation, auth mapping, safety
boundary, and report parser work before testing an authorized target.
