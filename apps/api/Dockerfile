# syntax=docker/dockerfile:1.7
# Multi-stage build: dependencies are resolved with uv in a builder stage; the runtime
# image contains only the virtualenv and source, runs as an unprivileged user and has
# no compiler toolchain or package manager cache.

ARG PYTHON_VERSION=3.12
ARG UV_VERSION=0.11.23

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---------- base ----------
FROM python:${PYTHON_VERSION}-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
RUN groupadd --system --gid 10001 keygate \
    && useradd --system --uid 10001 --gid keygate --no-create-home --shell /usr/sbin/nologin keygate

# ---------- builder: production dependencies only ----------
FROM base AS builder
COPY --from=uv /uv /usr/local/bin/uv
# Install deps first (cached layer), then the project itself.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-dev --no-install-project
COPY pyproject.toml uv.lock alembic.ini ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---------- dev: hot reload, dev tools, source bind-mounted by compose ----------
FROM base AS dev
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_CACHE_DIR=/tmp/uv-cache
RUN mkdir -p /app/.venv && chown keygate:keygate /app /app/.venv
USER keygate
COPY --chown=keygate:keygate pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
ENV PATH="/app/.venv/bin:${PATH}"
EXPOSE 8000
CMD ["sh", "-c", "uv sync --frozen && exec uvicorn keygate.main:create_app --factory --host 0.0.0.0 --port 8000 --reload --reload-dir src --no-access-log"]

# ---------- runtime: minimal production image ----------
FROM base AS runtime
# X-Forwarded-For is only honoured from these addresses (set to the reverse proxy's IP).
ENV FORWARDED_ALLOW_IPS=127.0.0.1
COPY --from=builder --chown=keygate:keygate /app/.venv /app/.venv
COPY --from=builder --chown=keygate:keygate /app/alembic.ini /app/alembic.ini
COPY --from=builder --chown=keygate:keygate /app/src/keygate/db/migrations /app/src/keygate/db/migrations
ENV PATH="/app/.venv/bin:${PATH}"
USER keygate
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]
CMD ["uvicorn", "keygate.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers"]
