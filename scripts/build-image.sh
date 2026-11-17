#!/usr/bin/env bash
# Builds an app's runtime image with BuildKit, attaches BuildKit's own SBOM and
# SLSA provenance as attestations, pushes it to a LOCAL registry, and pulls it
# back as poc-<app>:local. Every SBOM generator then scans exactly that image,
# and every SBOM can name the same digest (needed later to sign/attest it).
#
# Usage: scripts/build-image.sh <app> [out-root]
# Env:   REGISTRY_PORT (default 5055; 5000 is often taken)
#
# Output in <out-root>/<app>/:
#   artifact.json                image name, index + manifest digest, image ID
#   buildkit-image.spdx.json     BuildKit's SBOM attestation (generator #5)
#   buildkit-provenance.json     BuildKit's SLSA provenance attestation
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
APP_DIR="apps/$APP"
[[ -f "$APP_DIR/Dockerfile" ]] || { echo "error: $APP_DIR/Dockerfile not found" >&2; exit 1; }

# shared BuildKit builder + local registry (scripts/buildkit.sh)
source "$(dirname "$0")/buildkit.sh"
REGISTRY="$BK_REGISTRY"
BUILDER="$BK_BUILDER"
SBOM_SCANNER="docker/buildkit-syft-scanner:stable-1@sha256:873a7458c3c8ac8e32c7b796c10e1600b07b963d2aa000a72a2d97aaaa2d6315"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
TAG="$REGISTRY/poc-$APP:${COMMIT:0:12}"
LOCAL_TAG="poc-$APP:local"
TIMEOUT="${STEP_TIMEOUT:-900}"

OUT="$OUT_ROOT/$APP"
mkdir -p "$OUT" "$OUT_ROOT/.cache"
log() { echo "==> [$APP] $*"; }

# --- shared infrastructure: one registry + one BuildKit builder (parallel-safe)
bk_ensure "$OUT_ROOT"

# --- build + attest + push ------------------------------------------------------
log "build $TAG (SBOM + provenance attestations)"
start=$SECONDS
timeout --kill-after=30 "$TIMEOUT" docker buildx build --builder "$BUILDER" --progress=plain \
  --target runtime \
  --sbom="generator=$SBOM_SCANNER" --provenance=mode=max \
  --label "org.opencontainers.image.revision=$COMMIT" \
  --label "org.opencontainers.image.title=poc-$APP" \
  -t "$TAG" --push "$APP_DIR" > "$OUT_ROOT/.cache/build-$APP.log" 2>&1 \
  || { echo "FAIL [$APP] build. Last lines:" >&2; tail -30 "$OUT_ROOT/.cache/build-$APP.log" >&2; exit 1; }
log "build ok ($((SECONDS - start))s)"

# --- pull the pushed image back, so local tools scan the identical artifact ----
docker pull -q "$TAG" > /dev/null
docker tag "$TAG" "$LOCAL_TAG"

index_digest=$(docker buildx imagetools inspect "$TAG" --format '{{json .Manifest}}' | jq -r .digest)
manifest_digest=$(docker buildx imagetools inspect "$TAG" --format '{{json .Manifest}}' \
  | jq -r '.manifests[] | select(.platform.os == "linux") | .digest')
image_id=$(docker image inspect -f '{{.Id}}' "$LOCAL_TAG")

docker buildx imagetools inspect "$TAG" --format '{{json .SBOM}}' \
  | jq '.SPDX' > "$OUT/buildkit-image.spdx.json"
docker buildx imagetools inspect "$TAG" --format '{{json .Provenance}}' \
  | jq '.SLSA' > "$OUT/buildkit-provenance.json"

jq -n --arg app "$APP" --arg image "$TAG" --arg local "$LOCAL_TAG" \
      --arg index "$index_digest" --arg manifest "$manifest_digest" --arg id "$image_id" \
      --arg commit "$COMMIT" --arg built "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{app: $app, image: $image, local_tag: $local, index_digest: $index,
    manifest_digest: $manifest, image_id: $id, commit: $commit, built_at: $built}' \
  > "$OUT/artifact.json"
log "artifact $TAG@$index_digest"
