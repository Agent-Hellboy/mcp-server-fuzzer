# Run a first assessment

This guide gets a researcher from installation to a small, reproducible MCP
assessment. Use the [audit workflow](audit-workflow.md) when the run is part of
a formal engagement or report.

## 1. Install the client

```bash
python -m pip install mcp-fuzzer
mcp-fuzzer --version
mcp-fuzzer --help
```

For a source checkout:

```bash
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
python -m pip install -e .
```

## 2. Identify the target boundary

| Target | `--protocol` | `--endpoint` |
| --- | --- | --- |
| HTTP or HTTPS MCP endpoint | `http` or `https` | URL, for example `https://target.example/mcp` |
| SSE endpoint | `sse` | URL, for example `https://target.example/sse` |
| Streamable HTTP endpoint | `streamablehttp` | URL, for example `https://target.example/mcp` |
| Local server process | `stdio` | Command string, for example `python server.py` |

Record the exact endpoint or command, target revision, transport, negotiated
protocol version, credentials, and permitted side effects before testing.

## 3. Run a bounded baseline

For a remote endpoint:

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

For a local stdio fixture:

```bash
mkdir -p fuzz-sandbox
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --phase realistic \
  --runs 5 \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --seed 42 \
  --output-dir reports/baseline
```

The baseline establishes reachability, discovery, normal responses, and a
reproducible starting point. A target that cannot be reached or exposes no
usable tools is a blocked assessment; use `--fail-if-no-tools` when that state
must produce a non-zero exit.

## 4. Expand deliberately

Use one question per run while you learn the target:

```bash
# Tool argument and result handling
mcp-fuzzer --mode tools --phase aggressive \
  --protocol streamablehttp --endpoint https://target.example/mcp \
  --runs 20 --seed 42 --output-dir reports/tools-aggressive

# Protocol and schema behavior
mcp-fuzzer --mode protocol --protocol-phase aggressive \
  --protocol streamablehttp --endpoint https://target.example/mcp \
  --runs-per-type 5 --output-dir reports/protocol

# Tools, schemas, metadata, and evidence-backed security oracles
mcp-fuzzer --mode tools --phase aggressive \
  --protocol streamablehttp --endpoint https://target.example/mcp \
  --security-audit --runs 20 --output-dir reports/security
```

Use `--tool NAME` to focus on one tool, `--protocol-type TYPE` to focus a
protocol run, `--stateful` for learned sequences, and `--spec-schema-version`
when the target needs a specific MCP schema.

## 5. Add authentication intentionally

Use dedicated assessment credentials and the narrowest scope available. The
CLI supports `--auth-config`, `--auth-env`, and the MCP OAuth flow via `--oauth`.
For the target's authentication boundary, add the read-only `--auth-audit`:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol https \
  --endpoint https://target.example/mcp \
  --auth-env \
  --auth-audit \
  --security-audit \
  --runs 10 \
  --output-dir reports/authenticated
```

`--auth-audit-intrusive` can create OAuth registration state and probe redirect
handling. Use it only when the written authorization explicitly includes those
actions, and keep it separate from a baseline run.

## 6. Review the evidence

Start with `run_summary.json`, then `findings.json`, then any crash or export
artifacts. Read [Interpret evidence and findings](results.md) before assigning
severity or sharing a report. The CLI reports what it observed; it does not
decide exploitability or business impact for you.

## Optional: observe a local process

Install the optional sidecar for authorized stdio assessments:

```bash
python -m pip install "mcp-fuzzer[mcpfz-probe]"
```

Then provide the sidecar path and explicit observation boundaries:

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

The `fake` backend is suitable for portable tests. The `ebpf` backend requires
an isolated Linux environment and appropriate privileges. Runtime observation
is disabled by default, applies to stdio processes, and fails open if the
sidecar cannot observe an event.

## Next steps

- [Follow the full audit workflow](audit-workflow.md)
- [Use maintained local example servers](examples.md)
- [Configure repeatable assessments](../configuration/configuration.md)
- [Contain the target](../components/safety.md)
- [Interpret the output](results.md)
- [Automate evidence collection](../security-ci.md)
