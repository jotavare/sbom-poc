# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# ScanCode Toolkit (aboutcode-org) for one-off licence + copyright scans of an
# app's dependencies (scripts/scancode.sh). There is no official container
# image, so it is installed from its pinned PyPI release.
# python:3.12-slim pinned by digest (2026-11-17)
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
# native libraries ScanCode/extractcode use (archive extraction, file types)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 libpopt0 libbz2-1.0 liblzma5 zlib1g libmagic1 \
    && rm -rf /var/lib/apt/lists/*
# Install with ScanCode's own pinned requirements for the release as constraints:
# without them pip picks newer dependencies (e.g. pluggy 1.7), which break
# ScanCode's plugin loading ("did not find any 'pre_scan' hooks").
ADD --checksum=sha256:6548a6270f8f7f5479fd1d711e8f932f5653920aac1cffbd83d381e76f53eb76 \
    https://raw.githubusercontent.com/aboutcode-org/scancode-toolkit/v32.5.0/requirements.txt /tmp/constraints.txt
RUN pip install --no-cache-dir --root-user-action=ignore -c /tmp/constraints.txt scancode-toolkit==32.5.0 \
    && scancode --version
USER 10001:10001
ENTRYPOINT ["scancode"]
