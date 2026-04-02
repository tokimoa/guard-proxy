FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application
COPY app/ app/
COPY cli/ cli/
COPY data/ data/

# Create data directory for SQLite
RUN mkdir -p /app/data

EXPOSE 4873 4874 4875 8100

CMD ["uv", "run", "guard-proxy", "start"]
