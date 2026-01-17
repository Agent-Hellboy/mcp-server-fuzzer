# Docker Usage Guide

This directory contains Docker-related files for running MCP Server Fuzzer in a containerized environment.

## Quick Start

### Building the Image

```bash
# From project root
docker build -t mcp-fuzzer:latest .
```

### Running the Fuzzer

#### HTTP/SSE Server (Container as Client)

The container acts as the MCP client. Your server can run anywhere (host machine, remote server, etc.).

```bash
# Linux - use host network
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --output-dir /output

# macOS/Windows - use host.docker.internal
docker run --rm -it \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://host.docker.internal:8000 --output-dir /output
```

#### Stdio Server (Server Runs in Container)

The server runs as a subprocess inside the container for better isolation.

```bash
# Mount server code and run
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "python /servers/my_server.py" --output-dir /output
```

## Docker Compose

Use `docker-compose.yml` for easier configuration:

```bash
# Set environment variables
export SERVER_PATH=./servers
export CONFIG_PATH=./examples/config

# Run fuzzing
docker-compose run --rm fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "node /servers/my-server.js stdio" \
  --runs 50 \
  --output-dir /output
```

## Volume Mounts

- **`/output`**: Reports directory (mount your local `reports/` directory here)
- **`/servers`**: Server code/executables for stdio servers (read-only recommended)
- **`/config`**: Custom configuration files (optional)

## Network Configuration

### HTTP/SSE Servers

- **Linux**: Use `--network host` to access servers on host machine
- **macOS/Windows**: Use `host.docker.internal` hostname (automatically configured in docker-compose)
- **Remote Servers**: Use server's IP address or domain name directly

### Stdio Servers

No network configuration needed - server runs as subprocess in container.

## Examples

### Example 1: Fuzz Node.js Stdio Server

```bash
# 1. Prepare server
mkdir -p servers
cp my-server.js servers/

# 2. Run fuzzer
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode all \
  --protocol stdio \
  --endpoint "node /servers/my-server.js stdio" \
  --runs 100 \
  --enable-safety-system \
  --output-dir /output
```

### Example 2: Fuzz HTTP Server on Host

```bash
# Server runs on host at localhost:8000
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools \
  --protocol http \
  --endpoint http://localhost:8000 \
  --runs 50 \
  --output-dir /output
```

### Example 3: Fuzz Remote HTTP Server

```bash
# Server runs on remote host
docker run --rm -it \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools \
  --protocol http \
  --endpoint https://api.example.com/mcp \
  --runs 50 \
  --output-dir /output
```

## Security Considerations

1. **Non-root User**: Container runs as `fuzzer` user (UID 1000) for security
2. **Read-only Mounts**: Use `:ro` flag for server code mounts when possible
3. **Isolated Environment**: Stdio servers run in isolated container environment
4. **No Persistent Storage**: Reports written to mounted volume, not container filesystem

## Troubleshooting

### Cannot Connect to HTTP Server on Host

**Linux**: Use `--network host` flag
```bash
docker run --rm -it --network host ...
```

**macOS/Windows**: Use `host.docker.internal` hostname
```bash
docker run --rm -it ... --endpoint http://host.docker.internal:8000
```

### Server Not Found in Container

Make sure server code is mounted correctly:
```bash
-v $(pwd)/servers:/servers:ro
```

And use absolute paths in endpoint:
```bash
--endpoint "python /servers/my_server.py"
```

### Permission Denied

The container runs as non-root user. If you need to write to mounted volumes, ensure proper permissions:
```bash
chmod -R 777 reports/  # Or use appropriate permissions
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Fuzz MCP Server

on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive
      
      - name: Build Docker image
        run: docker build -t mcp-fuzzer:latest .
      
      - name: Run fuzzing
        run: |
          docker run --rm \
            -v $(pwd)/servers:/servers:ro \
            -v $(pwd)/reports:/output \
            mcp-fuzzer:latest \
            --mode all \
            --protocol stdio \
            --endpoint "node /servers/test-server.js stdio" \
            --runs 50 \
            --output-dir /output
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: fuzzing-reports
          path: reports/
```
