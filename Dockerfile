FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

# Configure UV:
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_TOOL_BIN_DIR=/usr/local/bin

# Install dependencies:
WORKDIR /app

ADD pyproject.toml uv.lock README.md  /app
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-install-project --no-dev

# Install app:
ADD macen/ /app/macen/
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev

# Copy build application into fresh image:
FROM python:3.13-slim-bookworm
COPY --from=builder --chown=app:app /app /app

# Pick up scripts from venv directly
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["macen"]

LABEL org.opencontainers.image.source=https://github.com/mswart/macen
LABEL org.opencontainers.image.description="ACME client as server for dumb clients"
LABEL org.opencontainers.image.licenses=GPL

EXPOSE 1313
