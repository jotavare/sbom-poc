# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Static strace, built from the official source release, for runtime SBOMs
# (scripts/runtime-sbom.sh mounts it into each app container: a static binary
# works in any image, including distroless ones with no shell or libc).
#
# Source: https://github.com/strace/strace/releases/tag/v7.3 (2026-10-22).
# The SHA-256 below was pinned after verifying the release's PGP signature:
#   "Good signature from Dmitry V. Levin <ldv@strace.io>" (strace maintainer),
#   signing key fingerprint FB3D CD19 FF87 4735 E4F6 1CE6 4E9F E852 2F16 0EC2.

# alpine:3.22 pinned by digest (2026-11-17); musl links statically cleanly
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS build
RUN apk add --no-cache build-base linux-headers xz
ADD --checksum=sha256:529634c40910895a9a1f3c5c1e65da2ca9ed72fb158dfc4bcc89efdf05e39b72 \
    https://github.com/strace/strace/releases/download/v7.3/strace-7.3.tar.xz /tmp/
RUN tar -xJf /tmp/strace-7.3.tar.xz -C /tmp \
    && cd /tmp/strace-7.3 \
    && ./configure --quiet LDFLAGS=-static --enable-mpers=no \
    && make -s -j"$(nproc)" \
    && strip src/strace \
    && ./src/strace -V | head -1 \
    && cp src/strace /strace

FROM scratch AS strace
COPY --from=build /strace /strace
