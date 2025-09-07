# Network Policy System

The Network Policy system provides comprehensive access control for network resources with flexible, consistent host normalization and automatic safety features.

## Overview

The network policy system consists of several components:

1. **Host Normalization** - Standardizes hostnames for consistent comparison
2. **Access Control** - Enforces rules about which hosts can be contacted
3. **Safe Redirect Resolution** - Prevents redirect-based access control bypasses
4. **Proxy Prevention** - Strips proxy environment variables from subprocesses

## Components

### Host Normalization

The system automatically normalizes host strings in a consistent way:

```python
from urllib.parse import urlparse
import ipaddress

def _normalize_host(host: str) -> str:
    """Normalize host to handle URLs, mixed case, etc."""
    if not host:
        return ""
    s = host.strip().lower()
    # Accept bare host or URL; extract hostname if URL-like
    if "://" in s:
        parsed = urlparse(s)
        host = (parsed.hostname or "").strip().lower()
    else:
        # Handle bracketed IPv6 like "[::1]:8080"
        if s.startswith("["):
            end = s.find("]")
            host = s[1:end] if end != -1 else s
        else:
            # Handle unbracketed forms:
            # 1) Plain IPv6 literal (multiple colons, no port)
            # 2) IPv6 with trailing :port (non-standard but seen in the wild)
            if s.count(":") > 1:
                # Try to split off a trailing port only if it looks like one
                left, sep, right = s.rpartition(":")
                if sep and right.isdigit():
                    try:
                        port = int(right)
                        if 0 <= port <= 65535 and isinstance(ipaddress.ip_address(left), ipaddress.IPv6Address):
                            host = left
                        else:
                            host = s
                    except ValueError:
                        host = s
                else:
                    host = s
            else:
                # Otherwise, treat as hostname[:port]
                host = s.split(":", 1)[0]
    # Normalize trailing dot for FQDNs
    return host.rstrip(".")
```

This ensures:
- Case insensitivity (`example.com` = `EXAMPLE.COM`)
- Protocol handling (`http://example.com` -> `example.com`)
- Port stripping (`example.com:80` -> `example.com`)
- Whitespace handling (`  example.com  ` -> `example.com`)
- Special cases for IPv6 addresses

### Network Access Control

The system enforces access control with the following features:

- **Default-deny policy**: Only explicitly allowed hosts can be contacted
- **Local host allowlist**: Standard local addresses (localhost, 127.0.0.1, etc.)
- **Runtime configuration**: Dynamically adjust policy at runtime
- **Additional allowed hosts**: Add specific hosts to the allowlist

```python
# Configure network policy
configure_network_policy(
    deny_network_by_default=True,
    extra_allowed_hosts=["api.example.com", "data.example.com"],
    reset_allowed_hosts=False
)

# Check if a host is allowed
is_allowed = is_host_allowed("http://api.example.com/v1/data")
```

### Safe Redirect Resolution

The system prevents redirect-based bypasses:

```python
# Safe redirect resolution
target = resolve_redirect_safely(
    base_url="https://allowed.example.com/api",
    location="/redirect?to=https://evil.example.com",
    allowed_hosts=None,  # Use default allowlist
    deny_network_by_default=True
)
# target will be None since it redirects to a disallowed host
```

### Proxy Prevention

The system prevents subprocesses from using proxy environment variables:

```python
# Sanitize environment for subprocess
import os
safe_env = sanitize_subprocess_env(source_env=os.environ)
# HTTP_PROXY, HTTPS_PROXY, etc. will be removed
```

## Configuration

### Default Configuration

The system uses these default settings:

```python
SAFETY_LOCAL_HOSTS = [
    "localhost", "127.0.0.1", "::1"
]
SAFETY_NO_NETWORK_DEFAULT = True

# (Optional, recommended) Example explicit blocks to mitigate SSRF:
# SAFETY_BLOCKED_CIDRS = [
#   "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
#   "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
#   "::/128", "::1/128", "fc00::/7", "fe80::/10"
# ]
```

### Runtime Configuration

You can configure the system at runtime:

```python
# Add specific hosts to allowlist
configure_network_policy(
    extra_allowed_hosts=["api.example.com"]
)

# Reset allowed hosts
configure_network_policy(
    reset_allowed_hosts=True
)

# Allow all hosts (disable protection)
configure_network_policy(
    deny_network_by_default=False
)
```

## Usage Examples

### Basic Host Checking

```python
from mcp_fuzzer.safety_system.policy import is_host_allowed

# Check if host is allowed
if is_host_allowed("https://api.example.com/v1/data"):
    # Proceed with request
    pass
else:
    # Host not allowed, abort
    pass
```

### Advanced Configuration

```python
from mcp_fuzzer.safety_system.policy import configure_network_policy

# Setup network policy for testing
configure_network_policy(
    deny_network_by_default=True,
    extra_allowed_hosts=["test1.example.com", "test2.example.com"],
    reset_allowed_hosts=True  # Clear previous allowlist
)
```

### Safe Subprocess Environment

```python
from mcp_fuzzer.safety_system.policy import sanitize_subprocess_env
import subprocess

# Create safe environment for subprocess
env = sanitize_subprocess_env()

# Launch subprocess safely
subprocess.Popen(["curl", "https://api.example.com"], env=env)
```

## Best Practices

1. **Always check hosts**: Use is_host_allowed before making network requests
2. **Sanitize redirects**: Use resolve_redirect_safely for all redirects
3. **Sanitize subprocess environments**: Use sanitize_subprocess_env for all subprocesses
4. **Standardize host handling**: Use the same normalization logic throughout
5. **Maintain explicit allowlists**: Only add hosts that are absolutely required

## Integration

The Network Policy system integrates with the following components:

- **HTTP Transport**: Enforces policy for all requests
- **Process Manager**: Uses sanitized environments
- **Safety System**: Part of comprehensive safety strategy
- **CLI Interface**: Allows configuration via command line
