# Docker Quick Start

## TL;DR

```bash
# Build
docker build -t mcp-fuzzer:latest .

# Fuzz HTTP server (container = client)
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --output-dir /output

# Fuzz stdio server (server runs in container)
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "python /servers/my_server.py" --output-dir /output
```

## Common Patterns

### Pattern 1: HTTP Server on Host Machine

**Linux:**
```bash
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --output-dir /output
```

**macOS/Windows:**
```bash
docker run --rm -it \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://host.docker.internal:8000 --output-dir /output
```

### Pattern 2: Stdio Server from Host Filesystem

```bash
# Mount server directory
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "node /servers/my-server.js stdio" --output-dir /output
```

### Pattern 3: Remote HTTP Server

```bash
docker run --rm -it \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint https://api.example.com/mcp --output-dir /output
```

### Pattern 4: Using Docker Compose

```bash
# Stdio server
docker-compose run --rm fuzzer \
  --mode tools --protocol stdio --endpoint "node /servers/my-server.js stdio" --output-dir /output

# HTTP server (macOS/Windows)
docker-compose run --rm fuzzer \
  --mode tools --protocol http --endpoint http://host.docker.internal:8000 --output-dir /output

# HTTP server (Linux)
docker-compose -f docker-compose.host-network.yml run --rm fuzzer \
  --mode tools --protocol http --endpoint http://localhost:8000 --output-dir /output
```

## Volume Mounts Explained

- `-v $(pwd)/reports:/output` - Mount reports directory (writable)
- `-v $(pwd)/servers:/servers:ro` - Mount server code (read-only)
- `-v $(pwd)/config:/config:ro` - Mount config files (read-only, optional)

## Network Explained

- **`--network host`** (Linux only): Container uses host's network stack
- **`host.docker.internal`** (macOS/Windows): Special hostname to access host machine (Docker Engine 20.10+ for host-gateway)
- **Bridge network** (default): Container has isolated network, use IP/domain for remote servers

## Troubleshooting

**Can't connect to localhost server?**
- Linux: Use `--network host`
- macOS/Windows: Use `host.docker.internal` instead of `localhost`

**Server not found?**
- Check volume mount: `-v $(pwd)/servers:/servers:ro`
- Use absolute path in endpoint: `/servers/my-server.js`

**Permission denied?**
- Container runs as non-root user (UID 1000)
- Prefer ownership or group write access instead of world-writable permissions:
  - `sudo chown -R 1000:1000 reports/`
  - or `chmod 750 reports/` with matching group permissions
