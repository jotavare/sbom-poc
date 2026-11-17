# syntax=docker/dockerfile:1
# Base image pinned by digest (python:3.12-slim, 2026-11-16)
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv
COPY requirements.txt .
RUN pip install --root-user-action=ignore -r requirements.txt

# --- test stage: `docker build --target test .` runs the test suite ---
FROM base AS test
COPY requirements-dev.txt .
RUN pip install --root-user-action=ignore -r requirements-dev.txt
COPY . ./
RUN python -m pytest -q tests

# --- sbom stage: native OWASP generator (cyclonedx-py) on the installed environment.
#     The tool lives in its own venv so it does not appear in the SBOM itself.
FROM base AS sbom
RUN python -m venv /opt/cdx && /opt/cdx/bin/pip install --root-user-action=ignore cyclonedx-bom==8.0.1 \
    && /opt/cdx/bin/cyclonedx-py environment "$(command -v python)" \
       --output-format JSON --output-file /native-source.cdx.json

# --- sbom-export: `docker build --target sbom-export --output type=local,dest=<dir>`
FROM scratch AS sbom-export
COPY --from=sbom /native-source.cdx.json /

# --- runtime stage (default) ---
FROM base AS runtime
COPY app.py ./
RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]
