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
#
# PR-A audit fix (Bugbot HIGH on commit ce37238): the previous CMD was
# ``["python", "-m", "uvicorn", "src.query_api:app", "--host", "0.0.0.0", ...]``
# which bypassed the module-level safety check at ``src/query_api.py:88-102``.
# Anyone running ``docker run edgeguard-kg:latest`` directly (without
# compose) hit the uvicorn CLI flag and bound 0.0.0.0 unauthenticated —
# defeating the whole point of A6. Match the compose command shape so the
# Python module's safety check actually gates the bind for both invocation
# paths. Operators who want a non-loopback bind via ``docker run`` must
# set EDGEGUARD_API_HOST + EDGEGUARD_API_KEY (or EDGEGUARD_ALLOW_UNAUTH=1).
CMD ["python", "-m", "src.query_api"]
