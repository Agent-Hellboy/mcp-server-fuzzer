# Configure a repeatable assessment

Use configuration when a target, test matrix, and evidence policy need to be
repeated. Keep the target-specific file private when it contains endpoint
details or authentication references; do not commit secrets.

## Configuration precedence

Values are applied in this order:

1. CLI arguments, highest precedence.
2. The selected YAML configuration file.
3. Environment variables and project defaults.

Use `--config path/to/assessment.yaml` for an explicit file. Without `--config`,
the loader can discover the repository's standard `mcp-fuzzer.yml` or
`mcp-fuzzer.yaml` locations. Use `--validate-config FILE` to check that a YAML
file is readable and has a mapping at its top level.

## A security-assessment profile

This is a starting profile for an authorized remote target. Adjust the mode,
transport, endpoint, credentials, and run counts to the engagement:

```yaml
mode: tools
protocol: streamablehttp
endpoint: "https://target.example/mcp"
phase: realistic
protocol_phase: realistic
runs: 10
runs_per_type: 5
seed: 42
spec_schema_version: "2025-11-25"

# Security checks run after the selected fuzzing work.
security_audit: true
auth_audit: true
auth_audit_intrusive: false
fail_if_no_tools: true

timeout: 30.0
tool_timeout: 10.0
transport_retries: 1
log_level: INFO

output:
  directory: reports/baseline
  format: json
  types:
    - fuzzing_results
    - error_report
    - safety_summary
```

Use a second file or CLI overrides for aggressive probing:

```bash
mcp-fuzzer \
  --config assessment.yaml \
  --phase aggressive \
  --runs 20 \
  --seed 42 \
  --output-dir reports/aggressive
```

The accepted `output.format`, `output.schema`, `output.compress`, and
`output-session-id` settings are not all applied by the current standardized
writer. See [standardized output](../development/standardized-output.md) for
the implemented contract.

## Choose the assessment surface

| Key/flag | Use |
| --- | --- |
| `mode: tools` / `--mode tools` | Tool arguments and result behavior |
| `mode: protocol` / `--mode protocol` | Protocol message shapes and outcomes |
| `mode: resources` or `prompts` | Deterministic resource/prompt checks |
| `mode: all` | Tools plus protocol work and selected spec checks |
| `phase: realistic` | Establish normal behavior with valid-shaped values |
| `phase: aggressive` | Exercise malformed, boundary, and attack-oriented values |
| `phase: both` | Run both tool phases |
| `protocol_type` / `--protocol-type` | Focus protocol mode on one message type |
| `stateful: true` / `--stateful` | Exercise learned stateful protocol sequences |
| `spec_guard: true` | Run deterministic protocol/resource/prompt checks |
| `spec_schema_version` | Select a specific MCP schema/version path |
| `seed` / `--seed` | Improve reproduction of generated payloads |

## Protocol and schema version

The default schema version is `2025-11-25`. The repository currently includes
schema-driven paths for `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`,
and `2026-07-28`. Select the version that matches the target or the comparison
you are performing; record it with the assessment.

## Contain local stdio targets

For local processes, use a disposable root and deny non-local network access:

```yaml
protocol: stdio
endpoint: "python my_server.py"
enable_safety_system: true
fs_root: "./fuzz-sandbox"
no_network: true
allow_hosts: []
runtime_probe: false
```

The fuzzer's controls are not a full operating-system sandbox. Use a container
or VM for untrusted code. See [contain the target](../components/safety.md).

For optional runtime observation:

```yaml
runtime_probe: true
runtime_probe_backend: auto
runtime_probe_bin: "/path/to/mcpfz-probe"
runtime_probe_workspace: "./fuzz-sandbox"
runtime_probe_tmpdir: "/tmp"
runtime_probe_allow_exec:
  - "/usr/bin/date"
runtime_probe_allow_host:
  - "api.example.com"
```

Runtime observation applies to stdio processes, is disabled by default, and
fails open if the sidecar cannot start or observe an event.

## Authentication without leaking secrets

Use `--auth-config` for a JSON provider file or `--auth-env` for environment
variables. Prefer dedicated, short-lived assessment identities.

```json
{
  "providers": {
    "assessment": {
      "type": "oauth_client_credentials",
      "token_url": "https://auth.example.com/oauth/token",
      "client_id": "ASSESSMENT_CLIENT_ID",
      "client_secret": "REPLACE_WITH_SECRET",
      "scope": "tools.read"
    }
  },
  "default_provider": "assessment",
  "tool_mapping": {
    "example_tool": "assessment"
  }
}
```

```bash
mcp-fuzzer \
  --config assessment.yaml \
  --auth-config ./private/auth_config.json \
  --auth-audit \
  --output-dir reports/authenticated
```

The startup display masks sensitive configuration values, but target responses
and generated reports are not automatically safe to publish. Do not put real
tokens or client secrets in YAML, examples, shell history, or source control.

Supported environment variables include:

| Variable | Purpose |
| --- | --- |
| `MCP_API_KEY`, `MCP_HEADER_NAME`, `MCP_PREFIX` | API-key provider and header behavior |
| `MCP_USERNAME`, `MCP_PASSWORD` | Basic authentication |
| `MCP_OAUTH_TOKEN` | Existing bearer token |
| `MCP_OAUTH_TOKEN_URL`, `MCP_OAUTH_CLIENT_ID`, `MCP_OAUTH_CLIENT_SECRET`, `MCP_OAUTH_SCOPE` | Client-credentials flow |
| `MCP_CUSTOM_HEADERS` | JSON object of custom headers |
| `MCP_TOOL_AUTH_MAPPING`, `MCP_DEFAULT_AUTH_PROVIDER` | Auth selection by tool/default |
| `MCP_SPEC_SCHEMA_VERSION` | MCP schema/version selection |
| `MCPFZ_PROBE_*` | Optional runtime-probe settings |

Use `--oauth` when the fuzzer should perform the MCP OAuth flow. Choose
`--oauth-grant authorization_code` for a user-delegated PKCE flow or
`client_credentials` for a machine identity. Use `--oauth-no-token-cache` when
the engagement does not permit local token caching.

## Output and retention

```yaml
output:
  directory: reports/assessment
  format: json
  types:
    - fuzzing_results
    - safety_summary
```

The CLI also supports `--export-csv`, `--export-xml`, `--export-html`, and
`--export-markdown` for additional views. Treat every export as sensitive until
reviewed; use restricted storage and an explicit retention policy.

## Validate and debug

```bash
mcp-fuzzer --validate-config assessment.yaml
mcp-fuzzer --check-env
mcp-fuzzer --config assessment.yaml --log-level DEBUG
```

`--validate-config` checks YAML loading and top-level shape; it is not a full
security review of the target or an authorization check. Use the
[CLI reference](../development/reference.md) for all flags and
[network policy](network-policy.md) for the implementation-facing host policy.
