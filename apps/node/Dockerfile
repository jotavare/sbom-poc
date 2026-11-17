# syntax=docker/dockerfile:1
# node:24-slim pinned by digest (2026-11-17)
FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS base
ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false
WORKDIR /srv
COPY package.json package-lock.json ./

# --- test stage: installs dev deps and runs `node --test` ---
FROM base AS test
RUN npm ci --include=dev --ignore-scripts
COPY . .
RUN npm test

# --- sbom stage: native OWASP generator (cyclonedx-npm) on the production dependency tree
FROM base AS sbom
RUN npm ci --omit=dev --ignore-scripts \
    && npx --yes @cyclonedx/cyclonedx-npm@7.0.1 --omit dev --output-format JSON --spec-version 1.7 \
       --output-file /native-build.cdx.json

# --- sbom-export: copied out by scripts/generate-sbom.sh (docker create + docker cp)
FROM scratch AS sbom-export
COPY --from=sbom /native-build.cdx.json /

# --- deps stage: production dependencies, installed with npm in the build image
FROM base AS deps
RUN npm ci --omit=dev --ignore-scripts

# --- runtime stage (default): distroless Node, no npm/corepack/yarn, no shell, non-root ---
# The runtime SBOM showed the slim image's npm + corepack (145 packages, npm is
# Artistic-2.0) never run; distroless ships only the node binary.
# gcr.io/distroless/nodejs24-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a AS runtime
ENV NODE_ENV=production
WORKDIR /srv
COPY --from=deps /srv/node_modules ./node_modules
COPY package.json app.js ./
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["/nodejs/bin/node", "/srv/app.js"]
