# EdgeGuard-KG — production application image
# Multi-stage build: builder installs deps, final image is minimal.
#
# Build:  docker build -t edgeguard-kg .
# Run:    docker run --env-file .env -p 8000:8000 edgeguard-kg

# ── Stage 1: dependency builder ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools (needed for some C extensions).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install into a local prefix so we can copy just the installed packages.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime image ─────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# PR-B audit fix (Dependency MED-4 + first Trivy run): the python:3.12-slim
# base ships openssl 3.5.5-1~deb13u1 which is vulnerable to CVE-2026-28390
# (HIGH; OpenSSL DoS via NULL pointer dereference in CMS handling). The
# fixed version 3.5.5-1~deb13u2 is in the Debian security archive. Force
# the upgrade in the runtime stage so Trivy passes and the runtime image
# has the patched library. The same upgrade is applied in Dockerfile.airflow.
#
# This ``apt-get upgrade`` is narrowly scoped (-y --only-upgrade openssl
# libssl3t64 openssl-provider-legacy) — it does NOT do a full image upgrade,
# which could destabilize other packages. When the python:3.12-slim base
# itself is refreshed upstream with patched openssl, this RUN can be removed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade \
        openssl libssl3t64 openssl-provider-legacy \
 && rm -rf /var/lib/apt/lists/*

# Security: run as a non-root user.
RUN groupadd --gid 1001 edgeguard \
 && useradd  --uid 1001 --gid edgeguard --no-create-home --shell /sbin/nologin edgeguard

# Copy installed packages from builder.
COPY --from=builder /install /usr/local

# Copy application source ONLY — credentials must NEVER be baked into the image.
# Inject secrets at runtime via: docker run --env-file .env ...
# or Docker secrets / Kubernetes secrets mounted as env vars.
WORKDIR /app
COPY src/ ./src/
# COPY runs as root; default file modes from the build context can be root-owned 600.
# Uvicorn workers run as `edgeguard` and must read every module under /app/src.
RUN chown -R edgeguard:edgeguard /app/src

# Ensure the src directory is on the Python path.
ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Runtime directories (checkpoints, state) will be mounted as volumes.
RUN install -d -o edgeguard -g edgeguard /app/checkpoints /app/state /app/logs

USER edgeguard

# Health check: hits the /health endpoint of the query API.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# Default command: start the query API.
# Override with "python src/run_pipeline.py" to run the pipeline instead.
CMD ["python", "-m", "uvicorn", "src.query_api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
