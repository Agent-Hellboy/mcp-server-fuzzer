# Maintained MCP assessment fixtures

These fixtures are for validating a local installation, transport behavior,
authentication mapping, safety controls, and report parsers before an
authorized assessment. They are intentionally small and are not security
certifications or real-world compatibility claims.

## Python HTTP fixture

Install the fixture dependencies in the environment used for the checkout:

```bash
python -m pip install "mcp[cli]" uvicorn
python examples/test_server.py
```

The server listens on `http://127.0.0.1:8000/mcp/` by default and exposes
public tools plus a `secure_tool` that requires a deterministic fixture token.
The token is `fixture-only-token` by default and can be changed with the
`REQUIRED_TOKEN` environment variable. Never reuse it outside this fixture.

Run a small baseline:

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

Exercise the protected tool with the checked-in fixture config:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://127.0.0.1:8000/mcp/ \
  --auth-config examples/auth_config.json \
  --runs 2 \
  --output-dir reports/example-auth
```

The config contains a deliberately non-secret test token. Do not use this
shape as permission to commit real credentials.

## Streamable HTTP fixture

```bash
python -m pip install mcp uvicorn anyio starlette
python examples/streamable_http_server.py --host 127.0.0.1 --port 3000
```

In another shell:

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

The Go and TypeScript directories contain small stdio servers with tools such
as `echo_tool`, `add_numbers`, and `normalize_text`.

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

## What these fixtures validate

- HTTP and Streamable HTTP discovery and tool calls.
- Stdio process startup, cleanup, timeout, and safety boundaries.
- Auth provider and tool-mapping behavior with a disposable token.
- Reproducible seeds and report artifact creation.
- Optional protocol/resource/prompt checks when the fixture exposes them.

For assessment recipes against an authorized target, see the
[documentation examples](../docs/getting-started/examples.md).
