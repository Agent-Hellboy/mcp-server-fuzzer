# Distroless runtime (no busybox) + slim builder
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG PIP_VERSION=24.3.1
ARG SETUPTOOLS_VERSION=75.6.0
ARG WHEEL_VERSION=0.44.0
ARG BUILD_ESSENTIAL_VERSION=12.9
ARG LIBFFI_DEV_VERSION=3.4.4-1
ARG LIBSSL_DEV_VERSION=3.0.18-1~deb12u1

WORKDIR /build

# Build dependencies for native wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential=${BUILD_ESSENTIAL_VERSION} \
    libffi-dev=${LIBFFI_DEV_VERSION} \
    libssl-dev=${LIBSSL_DEV_VERSION} \
 && rm -rf /var/lib/apt/lists/*

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

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
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

HEALTHCHECK NONE

ENTRYPOINT ["/usr/bin/python3", "-m", "mcp_fuzzer"]
CMD ["--help"]
