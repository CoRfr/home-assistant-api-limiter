# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install Poetry 2
RUN pip install --no-cache-dir poetry==2.2.1

# Configure Poetry to create venv in project directory
ENV POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies (without dev deps)
RUN poetry install --only main --no-root

# Copy application code
COPY ha_api_limiter/ ./ha_api_limiter/

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy virtualenv from builder
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Copy application code
COPY --from=builder --chown=appuser:appuser /app/ha_api_limiter ./ha_api_limiter/

# Create config directory
RUN mkdir -p /config && chown -R appuser:appuser /config /app

# Switch to non-root user
USER appuser

# Use the virtualenv
ENV PATH="/app/.venv/bin:$PATH"

# Environment variables (defaults)
ENV HA_URL=http://localhost:8123 \
    MODE=limit \
    CONFIG_PATH=/config/config.yaml \
    PORT=8080 \
    HOST=0.0.0.0

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run the application
CMD ["python", "-m", "ha_api_limiter.main"]
