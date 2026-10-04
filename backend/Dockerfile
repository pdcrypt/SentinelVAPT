# Build context is the repository root (see docker-compose.yml), because the
# backend imports the standalone scanner, analysis and reports packages (ADR
# 0001, 0009, 0010: backend -> scanner / analysis / reports are the allowed
# directions). Ignore rules: backend/Dockerfile.dockerignore.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# PDF rendering (WeasyPrint, ADR 0010) needs Pango and HarfBuzz; reports use
# the DejaVu fonts installed here, never fonts fetched at render time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# The scanner, the rule engine and the report renderer are installed from this
# repository, never resolved by name from a package index (avoids dependency
# confusion with a same-named public package).
COPY scanner /opt/sentinel-scanner
COPY analysis /opt/sentinel-analysis
COPY reports /opt/sentinel-reports
RUN pip install /opt/sentinel-scanner /opt/sentinel-analysis /opt/sentinel-reports

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
