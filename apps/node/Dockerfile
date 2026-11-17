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
    && npx --yes @cyclonedx/cyclonedx-npm@7.0.1 --omit dev --output-format JSON \
       --output-file /native-source.cdx.json

# --- sbom-export: `docker build --target sbom-export --output type=local,dest=<dir>`
FROM scratch AS sbom-export
COPY --from=sbom /native-source.cdx.json /

# --- runtime stage (default): production deps only ---
FROM base AS runtime
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY app.js ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["node", "-e", "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "app.js"]
