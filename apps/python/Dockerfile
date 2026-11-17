# syntax=docker/dockerfile:1
# Build image: Debian 13's own Python (3.13), the same interpreter the
# distroless runtime ships at /usr/bin/python3, so the venv built here runs there.
# debian:13-slim pinned by digest (2026-11-17)
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS base
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH

WORKDIR /srv
COPY requirements.txt .
RUN python3 -m venv /opt/venv && pip install -r requirements.txt

# --- test stage: `docker build --target test .` runs the test suite ---
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY . ./
RUN python -m pytest -q tests

# --- sbom stage: native OWASP generator (cyclonedx-py) on the installed environment.
#     The tool lives in its own venv so it does not appear in the SBOM itself.
FROM base AS sbom
RUN python3 -m venv /opt/cdx && /opt/cdx/bin/pip install cyclonedx-bom==8.0.1 \
    && /opt/cdx/bin/cyclonedx-py environment /opt/venv/bin/python \
       --output-format JSON --spec-version 1.7 --output-file /native-build.cdx.json

# --- sbom-export: copied out by scripts/generate-sbom.sh (docker create + docker cp)
FROM scratch AS sbom-export
COPY --from=sbom /native-build.cdx.json /

# --- runtime stage (default): distroless, no shell, no pip, non-root ---
# Only the venv and the app are copied: the build image's apt, pip and shell
# stay behind. Google marks the Python distroless image experimental.
# gcr.io/distroless/python3-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:6c4cb3bfa4b555429dd19541796a6ba6b30c84675b460bd0bd5072f7d5bdae71 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY --from=base /opt/venv /opt/venv
COPY app.py ./
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
ENTRYPOINT ["/opt/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]
