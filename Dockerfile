# Multi-stage Dockerfile for MCP Server Fuzzer
FROM python:3.12-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install the package (non-editable so runtime doesn't depend on /build)
RUN pip install --no-cache-dir .

# Runtime stage
FROM python:3.12-slim

# Install runtime dependencies (for stdio servers that might need system tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 fuzzer && \
    mkdir -p /app /output && \
    chown -R fuzzer:fuzzer /app /output

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy project files (needed for schemas and configs)
# Copy schemas directory (critical for spec guard)
COPY --chown=fuzzer:fuzzer schemas/ ./schemas/
# Copy mcp_fuzzer package
COPY --chown=fuzzer:fuzzer mcp_fuzzer/ ./mcp_fuzzer/
# Copy other necessary files
COPY --chown=fuzzer:fuzzer pyproject.toml README.md LICENSE ./

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_FUZZER_IN_DOCKER=1

# Switch to non-root user
USER fuzzer

# Default command
ENTRYPOINT ["mcp-fuzzer"]

# Default to help if no args provided
CMD ["--help"]
