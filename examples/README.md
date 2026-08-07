# Assessment fixtures

Small, self-contained MCP servers and configuration files for validating a
local installation before you point the fuzzer at a real target. Use them to
confirm that transports connect, authentication mapping works, safety controls
engage, and report artifacts parse.

These fixtures are deliberately insecure so the fuzzer has something to find.
They are not security certifications and not compatibility claims. Every
credential here is a throwaway literal; never reuse one outside these files.

The commands below assume `mcp-fuzzer` is on your `PATH`. From a git checkout,
substitute `python -m mcp_fuzzer`.

## Python HTTP fixture

`test_server.py` — a FastMCP server exposing three tools (`test_tool`,
`echo_tool`, `secure_tool`), one resource template (`test://items/{item_id}`),
and two prompts (`hello_prompt`, `summarise_prompt`). `secure_tool` requires a
bearer token; the other tools are public. `echo_tool` reflects its input
verbatim and `test_tool` accepts out-of-range values, so the fuzzer reliably
reports findings against it.

```bash
python -m pip install "mcp[cli]" uvicorn
python examples/test_server.py
```

It listens on `http://127.0.0.1:8000/mcp/`. The required token is
`fixture-only-token`, overridable with the `REQUIRED_TOKEN` environment
variable.

Run a baseline in another shell:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://127.0.0.1:8000/mcp/ \
  --phase realistic \
  --runs 3 \
  --seed 42 \
  --output-dir reports/example-http
```

Expect three tools discovered and a non-empty `findings.json`. `test_tool` and
`echo_tool` produce `accepted_malformed` findings because the fixture echoes
schema-invalid input back without error, and `echo_tool` also produces
`injection_reflection` because it returns an unsanitized `<script>` payload.
`secure_tool` fails every run with `Server error: {'code': -32001, 'message':
'Unauthorized'}` — that is correct, since this run sends no credential.

Now supply the token so `secure_tool` is actually reached:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://127.0.0.1:8000/mcp/ \
  --auth-config examples/auth_config.json \
  --runs 2 \
  --output-dir reports/example-auth
```

`auth_config.json` maps `secure_tool` to an `api_key` provider. The
`Unauthorized` exceptions disappear and `secure_tool` starts returning findings
of its own, which confirms per-tool auth mapping is working.

The same fixture also serves the non-tool modes:

```bash
mcp-fuzzer --mode resources --protocol http --endpoint http://127.0.0.1:8000/mcp/ --runs 2
mcp-fuzzer --mode prompts   --protocol http --endpoint http://127.0.0.1:8000/mcp/ --runs 2
mcp-fuzzer --mode protocol  --protocol http --endpoint http://127.0.0.1:8000/mcp/ --runs-per-type 2
```

## OAuth client-credentials fixture

`auth_test_server.py` — the same tool surface behind a machine-to-machine token
endpoint. It serves `POST /oauth/token`, mounts MCP at `/mcp`, and exposes
`/health` and `/metrics` so you can verify the fuzzer really authenticated.

```bash
python -m pip install "mcp[cli]" uvicorn starlette anyio
python examples/auth_test_server.py --host 127.0.0.1 --port 8765
```

This fixture does not publish RFC 9728 or RFC 8414 discovery metadata, so the
`--oauth` discovery flow does not apply to it. Drive it with an
`oauth_client_credentials` provider instead:

```json
{
  "default_provider": "machine",
  "providers": {
    "machine": {
      "type": "oauth_client_credentials",
      "token_url": "http://127.0.0.1:8765/oauth/token",
      "client_id": "mcp-fuzzer",
      "client_secret": "fixture-only-client-secret",
      "scope": "tools.read"
    }
  },
  "tool_mapping": { "secure_tool": "machine" }
}
```

```bash
mcp-fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://127.0.0.1:8765/mcp/ \
  --auth-config /path/to/that/config.json \
  --runs 2 \
  --output-dir reports/example-oauth
```

Then check `curl -s http://127.0.0.1:8765/metrics`. A successful run reports at
least one `token_requests` and a non-zero `authorized_tool_calls`, proving the
token was fetched once and reused. `tests/e2e/test_auth_server.sh` runs exactly
this sequence and asserts those metrics.

## Streamable HTTP fixture

`streamable_http_server.py` — a lowlevel MCP server on the Streamable HTTP
transport, for confirming session handling and the `streamablehttp` driver.

```bash
python -m pip install mcp uvicorn anyio starlette
python examples/streamable_http_server.py --host 127.0.0.1 --port 3000
```

It also accepts `--json-response` and `--log-level`.

```bash
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint http://127.0.0.1:3000/mcp \
  --phase realistic \
  --runs 3 \
  --output-dir reports/example-streamable
```

## Official SDK stdio fixtures

`go_stdio_server/` and `typescript-stdio-server/` are built on the official Go
and TypeScript MCP SDKs. Both expose `echo_tool`, `add_numbers`, and
`normalize_text`. Use them to exercise process startup, cleanup, timeouts, and
the stdio safety boundary against implementations the project does not control.

Go:

```bash
cd examples/go_stdio_server
go mod download
go build -o /tmp/mcp-fuzzer-go-stdio-server .
cd ../..
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint /tmp/mcp-fuzzer-go-stdio-server \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --runs 2 \
  --output-dir reports/example-go-stdio
```

TypeScript:

```bash
cd examples/typescript-stdio-server
npm ci
npm run build
cd ../..
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "node examples/typescript-stdio-server/dist/server.js" \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --runs 2 \
  --output-dir reports/example-typescript-stdio
```

Expect three tools discovered, the child process reaped at the end of the run,
and `fuzz-sandbox/` created as the only writable root. `--enable-safety-system`
puts blocking stubs for external launchers on `PATH` for the duration of the
run.

## Configuration files

`config/` holds configuration you can pass with `--config`:

- `mcp-fuzzer.yaml` and `mcp-fuzzer.yml` — a standard run configuration in both
  file extensions the loader accepts.
- `custom-transport-config.yaml` — wiring for a registered custom transport.

Check any of them without running a fuzz session:

```bash
mcp-fuzzer --validate-config examples/config/mcp-fuzzer.yaml
```

All three validate cleanly as shipped.

## Custom transport

`custom_websocket_transport.py` implements a WebSocket transport against the
project's transport interface. It is a reference for
`mcp_fuzzer.transport.register_custom_driver`, not a runnable fixture, and it
requires the `websockets` package. See
[custom transports](../docs/transport/custom-transports.md).

## Next steps

For recipes against an authorized target rather than a fixture, see the
[documentation examples](../docs/getting-started/examples.md). For how to read
what these runs produce, see
[understand run results](../docs/getting-started/results.md).
