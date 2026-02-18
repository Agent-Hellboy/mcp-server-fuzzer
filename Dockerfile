# Distroless runtime (no busybox) + slim builder
FROM python:3.11-slim AS builder

ARG PIP_ONLY_BINARY_OVERRIDE=:all:

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_PREFER_BINARY=1 \
    PIP_ONLY_BINARY=${PIP_ONLY_BINARY_OVERRIDE} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG PIP_VERSION=24.3.1
ARG SETUPTOOLS_VERSION=75.6.0
ARG WHEEL_VERSION=0.44.0
ARG BUILD_ESSENTIAL_VERSION=12.9
ARG LIBFFI_DEV_VERSION=3.4.4-1
ARG LIBSSL_DEV_VERSION=3.0.18-1~deb12u1
# Optional: install Rust toolchain only when needed for native wheels
ARG INSTALL_RUST_TOOLS=0

WORKDIR /build

# Build dependencies for native wheels
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential=${BUILD_ESSENTIAL_VERSION} \
      libffi-dev=${LIBFFI_DEV_VERSION} \
      libssl-dev=${LIBSSL_DEV_VERSION}; \
    if [ "${INSTALL_RUST_TOOLS}" = "1" ]; then \
      apt-get install -y --no-install-recommends cargo rustc; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# Copy metadata early
COPY pyproject.toml docker/requirements.runtime.txt ./

# Upgrade packaging tools
RUN python -m pip install --no-cache-dir --upgrade \
    pip==${PIP_VERSION} \
    setuptools==${SETUPTOOLS_VERSION} \
    wheel==${WHEEL_VERSION}

# Copy project
COPY . .

# Install runtime deps into isolated prefix, then the package itself
RUN python -m pip install --no-cache-dir --requirement docker/requirements.runtime.txt --prefix=/install \
 && python -m pip install --no-cache-dir --no-deps --prefix=/install .

# Prune extras from the install prefix
RUN rm -rf /install/lib/python3.11/site-packages/pip* /install/bin/pip* \
 && rm -rf /install/lib/python3.11/test /install/lib/python3.11/ensurepip \
           /install/lib/python3.11/idlelib /install/lib/python3.11/tkinter \
 && find /install/lib/python3.11 -type d \( -name "__pycache__" -o -name "tests" -o -name "test" -o -name "explore" \) -prune -exec rm -rf {} + \
 && find /install/lib/python3.11 -name '*.py[co]' -delete \
 && find /install -name '*.a' -delete \
 && find /install -type f \( -name '*.so' -o -name '*.so.*' \) -exec strip --strip-unneeded {} + || true

# Runtime stage: distroless python, nonroot by default (pinned digest)
FROM gcr.io/distroless/python3-debian12@sha256:8960438f63b66d97181dc38f0d42adb01f0789d4e9357c58a6e6c5a74df2f6e4

ARG PIP_ONLY_BINARY_OVERRIDE=:all:

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_PREFER_BINARY=1 \
    PIP_ONLY_BINARY=${PIP_ONLY_BINARY_OVERRIDE} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_FUZZER_IN_DOCKER=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

WORKDIR /app

# Copy installed artifacts from builder
COPY --from=builder /install /usr/local

# Copy runtime resources
COPY --chown=nonroot:nonroot schemas ./schemas

USER nonroot

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/python3", "-m", "mcp_fuzzer.healthcheck"]

ENTRYPOINT ["/usr/bin/python3", "-m", "mcp_fuzzer"]
CMD ["--help"]

# Debug runtime (shell + common utils) for troubleshooting without distroless
FROM python:3.11-slim AS runtime-debug

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_FUZZER_IN_DOCKER=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

WORKDIR /app

# Bring in installed package and resources
COPY --from=builder /install /usr/local
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY schemas ./schemas

# Align user with distroless/nonroot (uid/gid 65532)
RUN set -eux; \
    if ! getent group 65532 >/dev/null; then groupadd -r -g 65532 nonroot; fi; \
    if ! id -u 65532 >/dev/null 2>&1; then \
      useradd -r -u 65532 -g 65532 -d /app -s /bin/bash nonroot; \
    fi; \
    chown -R 65532:65532 /app /usr/local

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/bin/python3", "-m", "mcp_fuzzer.healthcheck"]

ENTRYPOINT ["python3", "-m", "mcp_fuzzer"]
CMD ["--help"]
