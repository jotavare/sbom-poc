# syntax=docker/dockerfile:1
# cdxgen (OWASP CycloneDX generator) packaged from npm.
#
# Why not the official image (ghcr.io/cdxgen/cdxgen)? It is ~16.6 GB and built
# for x86-64-v3 CPUs (AVX2), so it fails on older machines with
# "Fatal glibc error: CPU does not support x86-64-v3". The npm package runs
# anywhere Node 24 runs.
#
# Stages:
#   tool     image used for container-image scans (`cdxgen -t docker <tar>`)
#   runtime  node + cdxgen exported to a directory and mounted into each app's
#            own build image, so source scans run with the real toolchain
#            (pip, npm, go, mvn, cargo), like the native generators.

# node:24-slim pinned by digest (2026-11-17)
FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS tool
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
RUN npm install -g @cdxgen/cdxgen@13.8.0 && npm cache clean --force \
    && cdxgen --version
ENTRYPOINT ["cdxgen"]

FROM scratch AS runtime
COPY --from=tool /usr/local/bin/node /bin/node
COPY --from=tool /usr/local/lib/node_modules /lib/node_modules
