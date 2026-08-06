# Security Testing in CI

MCP Server Fuzzer is a testing client. Run it only against MCP servers and endpoints that your CI job is authorized to test.

## Recommended workflow

Keep the target isolated, set a bounded timeout, and save the machine-readable reports:

```yaml
- name: Fuzz MCP server
  run: |
    mcp-fuzzer \
      --mode all \
      --protocol streamablehttp \
      --endpoint http://127.0.0.1:8000/mcp \
      --runs 10 \
      --timeout 30 \
      --security-audit \
      --fail-if-no-tools \
      --output-dir reports

- name: Upload findings
  uses: actions/upload-artifact@v4
  with:
    name: mcp-fuzzer-findings
    path: reports/
```

Choose a failure policy for your project. The fuzzer writes findings for review; it does not automatically decide which severities should block a build.

## Local stdio targets

Use an explicit sandbox for local servers:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/ci-fuzz-sandbox" \
  --no-network \
  --runs 10 \
  --security-audit \
  --output-dir reports
```

Use --allow-host only for destinations required by the test. Runtime monitoring is separate and opt-in; see the [runtime monitoring guide](getting-started/getting-started.md#enable-runtime-monitoring).

## Reviewable artifacts

At minimum, publish:

- findings.json for security and reliability findings.
- run_summary.json for completion status and counts.
- crashes/ for available crash reproductions.

Do not upload reports containing credentials, tokens, private data, or server secrets to public artifacts. Redact or restrict artifacts according to your CI policy.

## Remote and intrusive checks

For remote endpoints, use HTTPS and dedicated test credentials. --auth-audit-intrusive can exercise dynamic client registration and redirect validation; keep it in a separately authorized job and never point it at production.

The --runtime-probe eBPF backend is intended for isolated Linux runners and stdio targets. It is disabled by default, does not scope remote HTTP/SSE processes, and fails open if the sidecar cannot start.
