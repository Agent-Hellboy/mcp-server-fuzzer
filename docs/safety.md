# Safety Guide

This guide explains the safety system in MCP Server Fuzzer, how to configure it, and best practices for safe fuzzing operations.

## Safety System Overview

The MCP Server Fuzzer includes a comprehensive safety system designed to protect your system during fuzzing operations. The safety system operates at multiple levels:

1. **Environment Detection** - Automatically detects production systems
2. **System Command Blocking** - Prevents execution of dangerous commands
3. **Filesystem Sandboxing** - Confines file operations to safe directories
4. **Process Isolation** - Safe subprocess handling with timeouts
5. **Input Sanitization** - Filters potentially dangerous input

## Environment Detection

### Automatic Detection

The safety system automatically detects production environments and applies stricter safety rules:

```python
def is_safe_test_environment():
    """Check if we're in a safe environment for dangerous tests."""
    # Don't run dangerous tests on production systems
    if (os.getenv("CI") or
        os.getenv("PRODUCTION") or
        os.getenv("DANGEROUS_TESTS_DISABLED")):
        return False

    # Don't run on systems with critical processes
    try:
        with open("/proc/1/comm", "r") as f:
            init_process = f.read().strip()
            if init_process in ["systemd", "init"]:
                return False
    except (OSError, IOError):
        pass

    # Don't run on systems with systemd
    if os.path.exists("/run/systemd/system"):
        return False

    # Don't run on systems with init
    if os.path.exists("/etc/inittab"):
        return False

    return True
```

### Environment Variables

Set these environment variables to control safety behavior:

```bash
# Disable dangerous tests
export DANGEROUS_TESTS_DISABLED=true

# Mark as production environment
export PRODUCTION=true

# CI environment
export CI=true
```

## 🚫 System Command Blocking

### Blocked Commands

The system blocker prevents execution of dangerous system commands:

```python
class SystemBlocker:
    def __init__(self):
        self.blocked_commands = {
            # File system operations
            "rm", "del", "format", "fdisk", "mkfs",

            # System control
            "shutdown", "reboot", "halt", "poweroff",

            # Process management
            "kill", "killall", "pkill", "xkill",

            # Network operations
            "iptables", "firewall-cmd", "ufw",

            # Package management
            "apt", "yum", "dnf", "pacman", "brew"
        }

        self.blocked_patterns = [
            # Dangerous file operations
            r"rm\s+-rf",
            r"del\s+/[sq]",
            r"format\s+[a-z]:",

            # System shutdown
            r"shutdown\s+",
            r"reboot\s+",
            r"halt\s+",

            # Dangerous process operations
            r"kill\s+-9",
            r"killall\s+-9"
        ]
```

### PATH Shim

The system blocker creates a shim PATH that redirects dangerous commands:

```python
def create_safe_path(self):
    """Create a safe PATH environment."""
    safe_path = "/tmp/mcp_fuzzer_safe_path"
    os.makedirs(safe_path, exist_ok=True)

    # Create fake executables for blocked commands
    for cmd in self.blocked_commands:
        fake_cmd_path = os.path.join(safe_path, cmd)
        with open(fake_cmd_path, "w") as f:
            f.write(f"""#!/bin/bash
echo "Command '{cmd}' is blocked by MCP Fuzzer safety system"
echo "This command could be dangerous and has been prevented from executing"
exit 1
""")
        os.chmod(fake_cmd_path, 0o755)

    return safe_path
```

## 📁 Filesystem Sandboxing

### Safe Directory Configuration

```bash
# Set custom filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --enable-safety-system --fs-root /tmp/mcp_fuzzer_safe

# Use environment variable
export MCP_FUZZER_FS_ROOT=/tmp/safe_dir
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --enable-safety-system
```

### Sandbox Implementation

```python
class FilesystemSandbox:
    def __init__(self, root_path: str):
        self.root_path = os.path.abspath(root_path)
        self.ensure_safe_directory()

    def ensure_safe_directory(self):
        """Ensure the sandbox directory exists and is safe."""
        if not os.path.exists(self.root_path):
            os.makedirs(self.root_path, mode=0o700)

        # Ensure directory is not in dangerous locations
        dangerous_paths = ["/", "/home", "/etc", "/var", "/usr", "/bin", "/sbin"]
        for dangerous in dangerous_paths:
            if self.root_path.startswith(dangerous) and self.root_path != dangerous:
                raise ValueError(f"Sandbox path {self.root_path} is in dangerous location")

    def is_path_safe(self, path: str) -> bool:
        """Check if a path is within the safe sandbox."""
        try:
            abs_path = os.path.abspath(path)
            return abs_path.startswith(self.root_path)
        except (OSError, ValueError):
            return False

    def sanitize_path(self, path: str) -> str:
        """Sanitize a path to ensure it's within the sandbox."""
        if not self.is_path_safe(path):
            return os.path.join(self.root_path, "safe_default")
        return path
```

## 🔒 Process Isolation

### Safe Subprocess Handling

```python
class SafeSubprocess:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    async def run_safe(self, command: str, **kwargs) -> Tuple[bytes, bytes]:
        """Run a command safely with timeout and isolation."""
        # Set up safe environment
        safe_env = self.create_safe_environment()

        # Create process with safety measures
        process = await asyncio.create_subprocess_exec(
            *command.split(),
            env=safe_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs
        )

        try:
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )

            # Check return code
            if process.returncode != 0:
                raise subprocess.CalledProcessError(
                    process.returncode, command, stdout, stderr
                )

            return stdout, stderr

        except asyncio.TimeoutError:
            # Kill process if it times out
            process.kill()
            await process.wait()
            raise TimeoutError(f"Command timed out after {self.timeout} seconds")

    def create_safe_environment(self) -> Dict[str, str]:
        """Create a safe environment for subprocess execution."""
        env = os.environ.copy()

        # Restrict PATH to safe locations
        env["PATH"] = "/usr/bin:/bin"

        # Remove dangerous environment variables
        dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"]
        for var in dangerous_vars:
            env.pop(var, None)

        return env
```

## 🧹 Input Sanitization

### Argument Filtering

```python
class InputSanitizer:
    def __init__(self):
        self.dangerous_patterns = [
            # SQL injection patterns
            r"(\b(union|select|insert|update|delete|drop|create|alter)\b)",
            r"(--|\b(and|or)\b\s+\d+\s*[=<>]\s*\d+)",

            # XSS patterns
            r"(<script[^>]*>.*?</script>)",
            r"(javascript:.*?)",
            r"(<img[^>]*on\w+\s*=)",

            # Path traversal patterns
            r"(\.\./|\.\.\\)",
            r"(/etc/passwd|/etc/shadow)",
            r"(c:\\windows\\system32)",

            # Command injection patterns
            r"(\b(rm|del|format|shutdown|reboot)\b)",
            r"(\||&|;|`|\$\(|\\n)"
        ]

        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE)
                                 for pattern in self.dangerous_patterns]

    def sanitize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize tool arguments to remove dangerous content."""
        sanitized = {}

        for key, value in arguments.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_arguments(value)
            elif isinstance(value, list):
                sanitized[key] = [self.sanitize_item(item) for item in value]
            else:
                sanitized[key] = value

        return sanitized

    def sanitize_string(self, value: str) -> str:
        """Sanitize a string value."""
        for pattern in self.compiled_patterns:
            if pattern.search(value):
                # Replace dangerous content with safe alternatives
                value = pattern.sub("[REDACTED_DANGEROUS_CONTENT]", value)

        return value
```

## Safety Configuration

### Basic Safety Configuration

```bash
# Enable safety system
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --enable-safety-system

# Set custom filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --enable-safety-system --fs-root /tmp/mcp_fuzzer_safe

# Disable argument-level safety (not recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --no-safety
```

### Advanced Safety Configuration

```bash
# Custom safety plugin
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --safety-plugin my_safety_module.SafetyProvider

# Retry with safety on interrupt
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --retry-with-safety-on-interrupt

# Combined safety options
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --enable-safety-system \
  --fs-root /tmp/safe_dir \
  --retry-with-safety-on-interrupt
```

### Environment Variable Configuration

```bash
# Core safety configuration
export MCP_FUZZER_SAFETY_ENABLED=true
export MCP_FUZZER_FS_ROOT=~/.mcp_fuzzer
export MCP_FUZZER_ENABLE_SYSTEM_BLOCKING=true

# Disable dangerous tests
export DANGEROUS_TESTS_DISABLED=true

# Mark as production environment
export PRODUCTION=true
```

## Custom Safety Providers

### Creating Custom Safety Provider

```python
class CustomSafetyProvider:
    """Custom safety provider for specific requirements."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocked_patterns = config.get("blocked_patterns", [])

    def get_safety(self) -> "SafetySystem":
        """Return a configured safety system."""
        return CustomSafetySystem(self.config)

    def is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed."""
        for pattern in self.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        return True

class CustomSafetySystem(SafetySystem):
    """Custom safety system with extended functionality."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.custom_rules = config.get("custom_rules", {})

    def filter_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Apply custom filtering rules."""
        # Apply base filtering
        filtered = super().filter_arguments(arguments)

        # Apply custom rules
        for rule_name, rule_func in self.custom_rules.items():
            filtered = rule_func(filtered)

        return filtered
```

### Using Custom Safety Provider

```bash
# Use custom safety provider
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --safety-plugin my_safety_module.CustomSafetyProvider

# With configuration
export MCP_FUZZER_SAFETY_CONFIG=/path/to/safety_config.json
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --safety-plugin my_safety_module.CustomSafetyProvider
```

## 🚨 Safety Alerts and Logging

### Safety Event Logging

```python
class SafetyLogger:
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or "mcp_fuzzer_safety.log"

    def log_blocked_command(self, command: str, reason: str):
        """Log a blocked command attempt."""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event": "command_blocked",
            "command": command,
            "reason": reason,
            "severity": "high"
        }

        self._write_log(log_entry)

    def log_safety_violation(self, violation_type: str, details: str):
        """Log a safety violation."""
        timestamp = datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "event": "safety_violation",
            "type": violation_type,
            "details": details,
            "severity": "critical"
        }

        self._write_log(log_entry)

    def _write_log(self, entry: Dict[str, Any]):
        """Write log entry to file."""
        with open(self.log_file, "a") as f:
            json.dump(entry, f)
            f.write("\n")
```

### Safety Monitoring

```bash
# Monitor safety logs
tail -f mcp_fuzzer_safety.log

# Check for safety violations
grep "safety_violation" mcp_fuzzer_safety.log

# Monitor blocked commands
grep "command_blocked" mcp_fuzzer_safety.log
```

## 📋 Safety Checklist

### Before Running Fuzzer

- [ ] Ensure you're not on a production system

- [ ] Set appropriate filesystem sandbox directory

- [ ] Enable safety system for stdio transport

- [ ] Review and configure blocked command patterns
- [ ] Set appropriate timeouts for your environment

### During Fuzzing

- [ ] Monitor safety logs for violations

- [ ] Check for blocked command attempts

- [ ] Verify filesystem operations are contained

- [ ] Monitor subprocess execution
- [ ] Watch for timeout issues

### After Fuzzing

- [ ] Review safety logs for any violations

- [ ] Check sandbox directory for unexpected files

- [ ] Verify no dangerous commands were executed

- [ ] Clean up temporary files and processes
- [ ] Document any safety issues encountered

## 🚨 Emergency Procedures

### Immediate Safety Stop

```bash
# Stop all fuzzer processes
pkill -f mcp-fuzzer

# Check for running subprocesses
ps aux | grep python

# Kill any hanging processes
kill -9 <process_id>
```

### Safety System Recovery

```bash
# Reset PATH environment
export PATH=/usr/bin:/bin

# Remove temporary safety directories
rm -rf /tmp/mcp_fuzzer_safe_path

# Check system integrity
ls -la /tmp/mcp_fuzzer*

# Review safety logs
tail -n 100 mcp_fuzzer_safety.log
```

### Reporting Safety Issues

If you encounter safety system issues:

1. **Stop all fuzzing operations immediately**
2. **Document the issue with timestamps and details**
3. **Check system integrity and logs**
4. **Report the issue to the project maintainers**
5. **Include safety logs and system information**

## Safety Testing

### Testing Safety Features

```bash
# Test command blocking
mcp-fuzzer --mode tools --protocol stdio --endpoint "echo 'test'" \
  --enable-safety-system --fs-root /tmp/test_safe

# Test filesystem sandboxing
mcp-fuzzer --mode tools --protocol stdio --endpoint "python -c 'import os; print(os.listdir(\"/\"))'" \
  --enable-safety-system --fs-root /tmp/test_safe

# Test timeout handling
mcp-fuzzer --mode tools --protocol stdio --endpoint "python -c 'import time; time.sleep(60)'" \
  --enable-safety-system --timeout 5
```

### Safety System Validation

```python
def test_safety_system():
    """Test safety system functionality."""
    safety = SafetySystem(fs_root="/tmp/test_safe")

    # Test environment detection
    assert safety.is_safe_environment() == True

    # Test command blocking
    blocker = SystemBlocker()
    assert blocker.is_blocked("rm -rf /") == True
    assert blocker.is_blocked("ls -la") == False

    # Test filesystem sandboxing
    sandbox = FilesystemSandbox("/tmp/test_safe")
    assert sandbox.is_path_safe("/tmp/test_safe/file.txt") == True
    assert sandbox.is_path_safe("/etc/passwd") == False
```

## 📚 Best Practices

### General Safety Guidelines

1. **Always enable safety system for stdio transport**
2. **Use dedicated sandbox directories for fuzzing**
3. **Monitor safety logs during operation**
4. **Set appropriate timeouts for your environment**
5. **Never run fuzzer on production systems**
6. **Regularly review and update safety rules**

### Transport-Specific Safety

- **HTTP/SSE**: Focus on input sanitization and timeout management

- **Stdio**: Enable full safety system with filesystem sandboxing

- **Custom**: Implement appropriate safety measures for your transport

### Environment Considerations

- **Development**: Can use aggressive fuzzing with safety system

- **Testing**: Use realistic fuzzing with safety system enabled

- **Production**: Never run fuzzer on production systems

- **CI/CD**: Use controlled environments with safety system

The safety system is designed to protect your system during fuzzing operations, but it should not be relied upon as the sole security measure. Always use it in controlled environments and monitor its operation closely.
