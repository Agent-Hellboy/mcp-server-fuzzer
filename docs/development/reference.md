# CLI reference for assessors

This is the operator reference for the current `mcp-fuzzer` command. It focuses
on flags that affect scope, inputs, authentication, safety, evidence, and
reproduction. For a task-based walkthrough, start with
[Run a first assessment](../getting-started/getting-started.md).

## Syntax

```bash
mcp-fuzzer [OPTIONS] --mode MODE --protocol TRANSPORT --endpoint TARGET
```

`--endpoint` is required for a real run. It is a URL for HTTP/SSE/Streamable
HTTP and a command string for stdio.

## Assessment selection

| Option | Default | Meaning |
| --- | --- | --- |
| `--mode {tools,protocol,resources,prompts,all}` | `all` | Select the MCP surface to exercise. |
| `--tool NAME` | none | Focus tool mode on one advertised tool. |
| `--phase {realistic,aggressive,both}` | `aggressive` | Tool-input phase: valid-shaped, attack/edge-oriented, or both. |
| `--protocol-phase {realistic,aggressive}` | `realistic` | Protocol/resource/prompt input phase. |
| `--runs N` | `10` | Tool runs per tool. |
| `--runs-per-type N` | `5` | Runs per protocol/resource/prompt type. |
| `--protocol-type TYPE` | none | Focus protocol mode on one message type; omission exercises the supported set. |
| `--stateful` / `--no-stateful` | off | Enable learned stateful protocol sequences. |
| `--stateful-runs N` | `5` | Number of learned stateful sequences. |
| `--seed N` | random | Seed payload generation for reproduction. |
| `--corpus` / `--no-corpus` | on | Enable per-target corpus persistence. |
| `--havoc` / `--no-havoc` | off | Enable stacked corpus mutations. |

Use [audit recipes](../getting-started/examples.md) to separate baseline,
aggressive, protocol, auth, and runtime evidence.

## Transport and protocol

| Option | Default | Meaning |
| --- | --- | --- |
| `--protocol {http,https,sse,stdio,streamablehttp}` | `http` | Transport driver. |
| `--endpoint TARGET` | none | URL or stdio command. |
| `--spec-schema-version VERSION` | negotiated/default | MCP schema version for schema-driven behavior, for example `2025-11-25` or `2026-07-28`. |
| `--timeout SECONDS` | `30.0` | General request timeout. |
| `--tool-timeout SECONDS` | unset | Per-tool timeout overriding `--timeout`. |
| `--transport-retries N` | `1` | Total transport attempts; `1` disables retrying. |
| `--transport-retry-delay SECONDS` | `0.5` | Initial retry delay. |
| `--transport-retry-backoff MULTIPLIER` | `2.0` | Retry delay multiplier. |
| `--transport-retry-max-delay SECONDS` | `5.0` | Retry delay ceiling. |
| `--transport-retry-jitter FACTOR` | `0.1` | Retry delay jitter. |

Generic `http`/`https` resolution depends on the selected MCP schema path. Use
`streamablehttp` when the target explicitly exposes that transport and record
the negotiated version in the assessment.

## Spec and deterministic checks

| Option | Default | Meaning |
| --- | --- | --- |
| `--spec-guard` / `--no-spec-guard` | on | Run deterministic checks before protocol/resource/prompt fuzzing. |
| `--spec-resource-uri URI` | none | Resource URI for resource checks. |
| `--spec-prompt-name NAME` | none | Prompt name for prompt checks. |
| `--spec-prompt-args JSON` | none | JSON object of prompt arguments. |

Supported protocol type names are listed in
[configuration](../configuration/configuration.md#protocol-and-schema-version)
and sourced from the runtime registry. Result schemas are validated by spec
guard but are not `--protocol-type` values.

## Security and authentication audits

| Option | Default | Meaning |
| --- | --- | --- |
| `--security-audit` | off | Inspect tool/schema metadata and correlate selected security oracles with fuzz evidence. |
| `--security-audit-intrusive` | off | Add the foreign-Origin DNS-rebinding probe; requires `--security-audit` and explicit authorization. |
| `--auth-audit` | off | Run read-only OAuth metadata, authorization behavior, and unauthenticated-tool checks where supported. |
| `--auth-audit-intrusive` | off | Add dynamic-registration and redirect probes; only use with explicit authorization. |
| `--fail-if-no-tools` | off, auto in CI/Docker | Exit non-zero when no usable tools are discovered. |
| `--allow-empty-tools` | off | Opt out of automatic no-tool failure for an explicitly expected zero-tool fixture. |

`--security-audit` can produce signals for tool/schema poisoning, hidden or
encoded instructions, ANSI/control content, trigger-conditioned metadata,
duplicate or drifting definitions, dangerous local-read/network-egress
combinations, cleartext remote transport, and evidence-backed command/path/SQL
or output-injection behavior. It also flags names that closely imitate common
tool names.

`--security-audit-intrusive` adds a foreign-Origin HTTP/SSE request. A
successful or redirecting response is reported as `missing_origin_validation`;
401/403 and unrelated protocol or routing errors are treated as inconclusive.
Use it only against a target and network boundary covered by the engagement.

`--auth-audit` is read-only by default. The intrusive variant may create OAuth
registration state and exercise redirect handling; keep it separate from a
baseline and never use it against production without written authorization.

## Authentication options

| Option | Default | Meaning |
| --- | --- | --- |
| `--auth-config FILE` | none | JSON provider file. |
| `--auth-env` | off | Resolve supported auth environment variables. |
| `--oauth` | off | Run the MCP OAuth flow against the target. |
| `--oauth-grant {authorization_code,client_credentials}` | `authorization_code` | User-delegated PKCE or machine-to-machine grant. |
| `--oauth-client-id ID` | env/none | Pre-registered client ID. |
| `--oauth-client-secret SECRET` | env/none | Confidential-client secret; prefer secret injection over shell history. |
| `--oauth-scope SCOPE` | env/none | Space-separated requested scopes. |
| `--oauth-client-id-metadata-url HTTPS_URL` | none | Client ID Metadata Document URL. |
| `--oauth-open-browser` | off | Open the authorization-code URL automatically. |
| `--oauth-no-token-cache` | off | Avoid the local OAuth token cache. |

Authentication provider examples and secret-handling guidance live in
[configuration](../configuration/configuration.md#authentication-without-leaking-secrets).

## Safety and host boundaries

| Option | Default | Meaning |
| --- | --- | --- |
| `--enable-safety-system` | off | Enable system-level command-blocking shims for the child process. |
| `--fs-root PATH` | `~/.mcp_fuzzer` | Root used to constrain fuzzer-generated filesystem paths. |
| `--no-safety` | off | Disable argument-level safety filtering; not recommended on an unisolated target. |
| `--no-network` | off | Disallow non-local fuzzer network access. |
| `--allow-host HOST` | none | Add an approved host while `--no-network` is active; repeatable. |
| `--safety-report` | off | Print the blocked-operation summary. |
| `--export-safety-data [FILE]` | timestamped | Save safety data as JSON. |
| `--retry-with-safety-on-interrupt` | off | Retry once with safety enabled after Ctrl-C. |

These are controls for the assessment client, not a complete OS sandbox. Use a
container or VM for untrusted local code. See [contain the target](../components/safety.md).

## Runtime observation for stdio

| Option | Default | Meaning |
| --- | --- | --- |
| `--runtime-probe` / `--no-runtime-probe` | env fallback | Enable optional `mcpfz-probe`. |
| `--runtime-probe-backend {ebpf,fake,auto}` | env/`ebpf` | Backend selection. |
| `--runtime-probe-bin PATH` | env/`mcpfz-probe` | Sidecar path. |
| `--runtime-probe-workspace PATH` | env/current directory | Allowed workspace root. |
| `--runtime-probe-tmpdir PATH` | env/`/tmp` | Allowed temporary root. |
| `--runtime-probe-allow-exec PATH` | none | Repeatable executable allowlist. |
| `--runtime-probe-allow-host HOST` | none | Repeatable host/host:port allowlist. |

The probe is opt-in, applies to local stdio process behavior, and fails open if
it cannot observe an event. It does not monitor remote transports.

## Output and diagnostics

| Option | Default | Meaning |
| --- | --- | --- |
| `--output-dir DIRECTORY` | `reports` | Directory for reports and exports. |
| `--output-format {json,yaml,csv,xml}` | `json` | Accepted standardized-output format; current writer emits JSON. |
| `--output-types TYPE [TYPE ...]` | all applicable | Space-separated standardized output types. |
| `--output-schema FILE` | none | Accepted custom schema path; not currently applied by the writer. |
| `--output-compress` | off | Accepted flag; not currently applied by the standardized writer. |
| `--output-session-id ID` | generated | Accepted override; not currently applied by the standardized writer. |
| `--export-csv FILE` | none | Additional CSV export. |
| `--export-xml FILE` | none | Additional XML export. |
| `--export-html FILE` | none | Additional HTML export. |
| `--export-markdown FILE` | none | Additional Markdown export. |
| `--verbose` | off | Use INFO-level default logging. |
| `--log-level LEVEL` | WARNING | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG`. |
| `--enable-aiomonitor` | off | Enable async debugging on the configured monitor port. |
| `--validate-config FILE` | none | Read and shape-check YAML, then exit. |
| `--check-env` | off | Validate known environment variables, then exit. |

Read [Interpret evidence and findings](../getting-started/results.md) before
processing artifact contents. Reports can contain target data and secrets.

## Process controls

| Option | Default | Meaning |
| --- | --- | --- |
| `--watchdog-check-interval SECONDS` | `1.0` | Watchdog polling interval. |
| `--watchdog-process-timeout SECONDS` | `30.0` | Stale-process threshold. |
| `--watchdog-extra-buffer SECONDS` | `5.0` | Grace period before termination. |
| `--watchdog-max-hang-time SECONDS` | `60.0` | Force-kill ceiling. |
| `--process-max-concurrency N` | `5` | Concurrent process operations. |
| `--max-concurrency N` | `5` | Concurrent client operations. |
| `--process-retry-count N` | `1` | Process-operation retries. |
| `--process-retry-delay SECONDS` | `1.0` | Delay between process retries. |

Tune these only after a baseline. High concurrency and retries can change the
target's behavior and make evidence harder to interpret.

## Common command patterns

```bash
# Validate a target profile without connecting
mcp-fuzzer --validate-config assessment.yaml

# Baseline with reproducible payload generation
mcp-fuzzer --config assessment.yaml --phase realistic --seed 42 \
  --output-dir reports/baseline

# Focus one tool with aggressive inputs
mcp-fuzzer --mode tools --tool NAME --phase aggressive \
  --protocol streamablehttp --endpoint https://target.example/mcp \
  --security-audit --runs 20 --seed 42 --output-dir reports/tool-NAME

# CI target usability check
mcp-fuzzer --mode all --protocol streamablehttp \
  --endpoint http://127.0.0.1:8000/mcp --security-audit \
  --fail-if-no-tools --output-dir reports/ci
```

For config precedence, environment variables, protocol type values, and
authentication provider JSON, use [configuration](../configuration/configuration.md).
