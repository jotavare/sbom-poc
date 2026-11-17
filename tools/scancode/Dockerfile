# syntax=docker/dockerfile:1
# ScanCode Toolkit (aboutcode-org) for one-off licence + copyright scans of an
# app's dependencies (scripts/scancode.sh). There is no official container
# image, so it is installed from its pinned PyPI release.
# python:3.12-slim pinned by digest (2026-11-17)
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
# native libraries ScanCode/extractcode use (archive extraction, file types)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libpopt0 libbz2-1.0 liblzma5 zlib1g libmagic1 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir --root-user-action=ignore scancode-toolkit==32.5.0 \
    && scancode --version
USER 10001:10001
ENTRYPOINT ["scancode"]
