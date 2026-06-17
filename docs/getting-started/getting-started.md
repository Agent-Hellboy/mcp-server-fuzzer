# Getting Started

This guide provides instructions for installing and configuring MCP Server Fuzzer.

## Installation

### From PyPI (Recommended)

```bash
pip install mcp-fuzzer
```

### Docker (Quick Start)

The container runs as a non-root user (UID 1000). Make sure your output directory is writable.

**Linux (HTTP server on host):**

```bash
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/examples/config:/config:ro \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --runs 10
```

**macOS/Windows (HTTP server on host):**

```bash
docker run --rm -it \
  -v $(pwd)/reports:/output \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/examples/config:/config:ro \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://host.docker.internal:8000 --runs 10
```

If you hit permission errors, ensure the output directory is writable by UID 1000:

```bash
sudo chown -R 1000:1000 reports/
```

### From Source

```bash
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
# If you already cloned without submodules, run:
git submodule update --init --recursive
pip install -e .
```

### Verify Installation

```bash
mcp-fuzzer --help
```

You should see the help output with all available options.

## Quick Start

### 1. Set Up Your MCP Server

First, ensure you have an MCP server running. You can use any of these transport protocols:

- **HTTP**: `http://localhost:8000`

- **SSE**: `http://localhost:8000/sse`

- **Stdio**: `python my_server.py`

- **StreamableHTTP**: `http://localhost:8000/mcp` (use `--protocol streamablehttp`)

### 2. Run Basic Fuzzing

#### Tool Fuzzing (Default Mode)

```bash
# Basic tool fuzzing (all tools)
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# With verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --verbose

# With safety system enabled for a local stdio server
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --runs 5 --enable-safety-system
```

#### Single Tool Fuzzing

```bash
# Fuzz only a specific tool
mcp-fuzzer --mode tools --tool analyze_repository --protocol http --endpoint http://localhost:8000 --runs 20

# Fuzz a specific tool with both phases
mcp-fuzzer --mode tools --tool generate_terraform --phase both --protocol http --endpoint http://localhost:8000 --runs 15
```

#### Protocol Fuzzing

```bash
# Basic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# With verbose output
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5 --verbose
```

Use `--protocol-phase aggressive` when you want malformed protocol payloads.

### 3. View Results

Results are displayed in beautiful, colorized tables showing:

- **Success Rate**: Percentage of successful operations
- **Exception Count**: Number of errors encountered
- **Example Exceptions**: Sample error messages for debugging
- **Overall Statistics**: Summary across all tools/protocols
- **Safety Data**: Blocked operations and risk assessments (when enabled)

### 4. Generate Reports

The MCP Fuzzer automatically generates comprehensive reports for each fuzzing session:

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --output-dir "my_reports"

# Generate comprehensive safety report
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --export-safety-data
```

Each fuzzing session creates `session_id`-based reports:
- **`fuzzing_report_<session_id>.json`** - Complete structured data for analysis
- **`fuzzing_report_<session_id>.txt`** - Human-readable summary for sharing
- **`safety_report_<session_id>.json`** - Detailed safety system data (if enabled)

Standardized JSON outputs are also written under
`reports/sessions/<session_id>/` with timestamped filenames (for example,
`*_fuzzing_results.json`).

## Configuration

MCP Fuzzer can be configured using environment variables, configuration files (YAML), or command-line arguments.

For detailed configuration information, see the [Configuration Guide](../configuration/configuration.md).

### Quick Configuration

Create a config file for quick setup:

```yaml
mode: "tools"
protocol: "http"
endpoint: "http://localhost:8000"
runs: 10
timeout: 30.0
log_level: "INFO"
enable_safety_system: true
fs_root: "~/.mcp_fuzzer"
```

## Fuzzing Modes

Tool fuzzing uses `--phase` (`realistic`, `aggressive`, or `both`). Protocol,
resource, prompt, and stateful fuzzing use `--protocol-phase` (`realistic` or
`aggressive`, default: `realistic`).

### Tool Fuzzing Mode

Tests individual tools with various argument combinations:

```bash
# Basic tool fuzzing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Realistic fuzzing (valid data only)
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint http://localhost:8000

# Aggressive fuzzing (malicious data)
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000

# Two-phase fuzzing (both realistic and aggressive)
mcp-fuzzer --mode tools --phase both --protocol http --endpoint http://localhost:8000
```

### Protocol Fuzzing Mode

Tests MCP protocol types with various message structures:

```bash
# Basic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# Realistic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase realistic --protocol http --endpoint http://localhost:8000

# Aggressive protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase aggressive --protocol http --endpoint http://localhost:8000
```

### Resource and Prompt Modes

These modes run spec-guard checks (unless `--spec-guard` is disabled) and then
fuzz the related request types.

```bash
# Resource endpoints
mcp-fuzzer --mode resources --protocol http --endpoint http://localhost:8000 \
  --spec-resource-uri file:///tmp/resource.txt

# Prompt endpoints
mcp-fuzzer --mode prompts --protocol http --endpoint http://localhost:8000 \
  --spec-prompt-name summarize \
  --spec-prompt-args '{"text":"hello"}'
```

### Stateful Sequences (Optional)

```bash
# Run learned protocol sequences after protocol fuzzing
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 \
  --stateful --stateful-runs 3
```

## Authentication

### Using Configuration File

Create `auth_config.json`:

```json
{
  "providers": {
    "openai_api": {
      "type": "api_key",
      "api_key": "sk-your-openai-api-key",
      "header_name": "Authorization"
    },
    "github_api": {
      "type": "api_key",
      "api_key": "ghp-your-github-token",
      "header_name": "Authorization"
    },
    "basic_auth": {
      "type": "basic",
      "username": "user",
      "password": "password"
    }
  },
  "tool_mapping": {
    "openai_chat": "openai_api",
    "github_search": "github_api",
    "secure_tool": "basic_auth"
  }
}
```

Use with fuzzer:

```bash
mcp-fuzzer --mode tools --protocol http --auth-config auth_config.json --endpoint http://localhost:8000
```

### Using Environment Variables

```bash
export MCP_API_KEY="sk-your-api-key"
export MCP_USERNAME="user"
export MCP_PASSWORD="password"

mcp-fuzzer --mode tools --protocol http --auth-env --endpoint http://localhost:8000
```

### MCP OAuth 2.1 Authorization (`--oauth`)

The methods above attach a **static** credential you already hold (an API key, a
bearer token, or a client id/secret for a known token endpoint). When the MCP
server is an OAuth 2.1 *protected resource* — it answers an unauthenticated
request with `401` and a `WWW-Authenticate: Bearer resource_metadata="..."`
header — the fuzzer can acquire a token for you with the `--oauth` flag. No
hand-built `auth_config.json` is needed.

`--oauth` runs the full MCP authorization flow (per the MCP 2025-11-25 spec):

1. **Discover** the Protected Resource Metadata (RFC 9728) and the Authorization
   Server Metadata (RFC 8414) starting from the endpoint's `.well-known`
   documents / `WWW-Authenticate` challenge.
2. **Obtain a client** — use a pre-registered `--oauth-client-id`, a Client ID
   Metadata Document URL, or fall back to Dynamic Client Registration (RFC 7591)
   if the server's authorization server supports it.
3. **Run the grant** — `authorization_code` with PKCE (browser, user-delegated)
   or `client_credentials` (machine-to-machine).
4. **Attach** the resulting bearer token to every fuzzing request and refresh it
   transparently when it expires.

The acquired token is cached on disk (under `~/.cache/mcp-fuzzer/oauth/`, or
`$XDG_CACHE_HOME/mcp-fuzzer/oauth/`) so the browser step happens at most once;
subsequent runs reuse or silently refresh it. Use `--oauth-no-token-cache` to
disable this.

#### Authorization code + PKCE (browser-based, default)

Use this for user-delegated access. The fuzzer starts a one-shot
`http://127.0.0.1:<port>/callback` loopback server, prints (or opens) the
authorization URL, and waits for the redirect after you log in.

```bash
mcp-fuzzer --mode tools --protocol streamablehttp \
  --endpoint https://your-server.example.com/mcp \
  --oauth --oauth-open-browser --runs 5
```

If the authorization server supports anonymous Dynamic Client Registration, the
command above needs nothing else — the fuzzer registers a public, PKCE-only
client on the fly with the exact loopback redirect URI. To reuse a
pre-registered client instead, pass `--oauth-client-id` (and
`--oauth-client-secret` for a confidential client). When using a pre-registered
client, its allowed redirect URIs must permit the loopback callback (e.g. a
`http://127.0.0.1/*` pattern), since the port is chosen at runtime.

Omit `--oauth-open-browser` for unattended runs: the URL is printed to the log
instead of hijacking a browser.

#### Client credentials (machine-to-machine, non-interactive)

Use this for a confidential service client with no user in the loop:

```bash
mcp-fuzzer --mode tools --protocol streamablehttp \
  --endpoint https://your-server.example.com/mcp \
  --oauth --oauth-grant client_credentials \
  --oauth-client-id my-service --oauth-client-secret "$CLIENT_SECRET" \
  --oauth-scope "openid profile email"
```

To keep the secret off the command line, set `MCP_OAUTH_CLIENT_ID`,
`MCP_OAUTH_CLIENT_SECRET`, and `MCP_OAUTH_SCOPE` in the environment; CLI flags
take precedence over these when both are present.

#### Example: a Keycloak-protected server

A server that returns
`WWW-Authenticate: Bearer resource_metadata="https://host/mcp/.well-known/oauth-protected-resource"`
pointing at a Keycloak realm works out of the box. If the realm allows anonymous
client registration and advertises PKCE `S256`, this is the entire command:

```bash
mcp-fuzzer --mode tools --protocol streamablehttp \
  --endpoint https://host/mcp --oauth --oauth-open-browser --runs 5
```

Log in as a realm test user when the browser opens; the fuzzer captures the
redirect, exchanges the code, and fuzzes the authenticated tools.

> See the [CLI Reference](../development/reference.md#authentication-options) for
> the full list of `--oauth*` flags.

### Authentication Security Audit

Beyond *using* OAuth to reach protected tools, the fuzzer can also *audit* a
server's OAuth deployment for the nine authentication flaw types described in
[*A First Measurement Study on Authentication Security in Real-World Remote MCP
Servers*](https://arxiv.org/abs/2605.22333). That study found ~40% of live
remote MCP servers expose tools without authentication, and that nearly every
authenticated server had at least one OAuth flaw.

Enable the read-only audit with `--auth-audit`:

```bash
mcp-fuzzer --mode tools --protocol streamablehttp \
  --endpoint https://host/mcp --auth-audit --runs 5
```

This performs only safe, read-only checks against the discovered authorization
server:

- **Metadata review** — missing PKCE `S256`, `plain`-only PKCE, deprecated
  grant types (`implicit`/`password`).
- **Authorization-endpoint probes** — blind client trust (unknown `client_id`
  accepted), PKCE downgrade (request without `code_challenge` accepted), weak
  state, and a consent-page heuristic.
- **Unauthenticated tool exposure** — when the server advertises OAuth but
  `tools/list` still returns tools without credentials (the paper's ~40% case).

For the intrusive probes — Dynamic Client Registration with an attacker redirect
URI and open-redirect tests — add `--auth-audit-intrusive`. These register state
on the target, so **only run them against servers you are authorized to test**:

```bash
mcp-fuzzer --mode tools --protocol streamablehttp \
  --endpoint https://host/mcp --auth-audit --auth-audit-intrusive --runs 5
```

Findings are written to `<output_dir>/findings.json`, each tagged with its paper
`flaw_id` (F1–F9) and citation, under a top-level `auth_audit` block. The audit
runs after the fuzz pass and never aborts it; if it can't run (no network, a
non-HTTP transport, or a discovery error) it logs the reason and is skipped
rather than reported as clean.

> `--auth-audit-intrusive` requires `--auth-audit`; passing it alone is a usage
> error. See the [CLI Reference](../development/reference.md#authentication-security-audit-options)
> for the full flag list and severity notes.

## Safety System

### Basic Safety Features

```bash
# Enable system command blocking (argument-level safety hooks are already on)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --enable-safety-system

# Set filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --fs-root /tmp/safe_dir

# Disable argument-level safety (not recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --no-safety

```

### Safety System Features

- **System Command Blocking**: Prevents execution of dangerous commands when `--enable-safety-system` is set

- **Filesystem Sandboxing**: Confines file operations to specified directories when `--fs-root` is set

- **Process Management**: Safe subprocess handling with watchdog timeouts

- **Safety Hooks**: Detection helpers available if you implement custom blocking

## Reporting and Output

### Basic Reporting

The MCP Fuzzer automatically generates comprehensive reports for each fuzzing session:

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --output-dir "my_reports"
```

### Enhanced Safety Reporting

```bash
# Show comprehensive safety report
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --export-safety-data

# Combine both features
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report --export-safety-data
```

### Generated Reports

Each fuzzing session creates:

- **`fuzzing_report_<session_id>.json`** - Complete structured data for analysis
- **`fuzzing_report_<session_id>.txt`** - Human-readable summary for sharing
- **`safety_report_<session_id>.json`** - Detailed safety system data (if enabled)

Standardized JSON outputs are also written under
`reports/sessions/<session_id>/` with timestamped filenames.

### Report Contents

- **Session metadata**: Mode, protocol, endpoint, runs, and timestamps
- **Tool results**: Success rates, exceptions, and safety blocks
- **Protocol results**: Error counts and success rates
- **Safety data**: Blocked operations, risk assessments, and system status
- **Summary statistics**: Overall success rates and execution timing

## Common Use Cases

### Testing Local Development Server

```bash
# Test local HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20

# Test local stdio server with safety
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --runs 10 --enable-safety-system
```

### Testing Production-Like Environment

```bash
# Test with realistic data only
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint https://api.example.com --runs 15

# Test protocol compliance
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase realistic --protocol http --endpoint https://api.example.com --runs-per-type 8
```

### Security Testing

```bash
# Aggressive fuzzing for security testing
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 25

# Protocol security testing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 15
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure your MCP server is running
2. **Authentication Errors**: Check your auth configuration
3. **Timeout Errors**: Increase timeout values for slow servers
4. **Permission Denied**: Check filesystem permissions for stdio transport

### Debug Mode

```bash
# Enable debug logging
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --log-level DEBUG

# Verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose
```

### Getting Help

```bash
# Show help
mcp-fuzzer --help

# Show help for specific mode
mcp-fuzzer --mode tools --help
mcp-fuzzer --mode protocol --help
```

## Next Steps

- **[Examples](examples.md)** - Working examples and configurations

- **[Architecture](../architecture/architecture.md)** - Understanding the system design

- **[Reference](../development/reference.md)** - Complete command reference

- **[Safety Guide](../components/safety.md)** - Advanced safety configuration
