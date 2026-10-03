# Build context is the repository root (see docker-compose.yml), because the
# backend imports the standalone scanner package (ADR 0001: backend -> scanner
# is the allowed direction). Ignore rules: backend/Dockerfile.dockerignore.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# The scanner is installed from this repository, never resolved by name from a
# package index (avoids dependency confusion with a same-named public package).
COPY scanner /opt/sentinel-scanner
RUN pip install /opt/sentinel-scanner

WORKDIR /app

# Install backend dependencies first for better layer caching.
COPY backend/pyproject.toml ./
RUN mkdir app && touch app/__init__.py \
    && pip install . \
    && rm -rf app

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./
RUN pip install --no-deps .

# Never run as root.
RUN useradd --create-home --uid 10001 sentinel
USER sentinel

EXPOSE 8000
CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8000"]
