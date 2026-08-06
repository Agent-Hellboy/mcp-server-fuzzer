# Network boundary for assessments

Network policy is an operational control for limiting where the fuzzer and
local target are allowed to connect. It is most useful for stdio assessments;
remote assessments still need an external runner or network boundary.

## CLI controls

```bash
mcp-fuzzer \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --no-network \
  --allow-host api.example.com \
  --allow-host 127.0.0.1 \
  --output-dir reports/network-scoped
```

| Control | Behavior |
| --- | --- |
| `--no-network` | Denies fuzzer access to non-local hosts. Loopback hosts remain available. |
| `--allow-host HOST` | Adds an approved hostname or host:port when `--no-network` is enabled; repeatable. |
| `no_network` | YAML equivalent of `--no-network`. |
| `allow_hosts` | YAML list equivalent of repeated `--allow-host`. |

The default policy allows network access. Do not mistake the default for a safe
boundary: choose the policy deliberately for every local target.

## What the policy covers

The fuzzer applies host normalization, allowlist checks, safe redirect handling,
and proxy-environment sanitization in the relevant transport and subprocess
paths. It is designed to reduce accidental egress from the assessment client.

It is not a network namespace, firewall, egress proxy, or complete containment
of arbitrary code executed by a server. Use a container/VM and an external
egress policy when the target is untrusted or when SSRF and data-exfiltration
behavior is in scope.

## Assessment guidance

1. Begin with `--no-network` for a local stdio target.
2. Add only the hosts required by the test, and record why each is allowed.
3. Keep OAuth discovery and redirect tests in a network environment explicitly
   authorized for those destinations.
4. Review runtime-probe `runtime.net_connect` evidence separately from the
   fuzzer's own transport policy.
5. Preserve the policy flags and allowlist in the assessment record.

For local process controls, see [contain the target](../components/safety.md).
For the implementation contracts, see the repository's transport and runtime
architecture pages.
