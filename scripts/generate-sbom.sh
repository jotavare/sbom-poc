#!/usr/bin/env bash
# Generates SBOMs for one app with several generators. Every tool runs as a
# pinned container (or inside the app's own Docker build), so local runs and CI
# behave the same.
#
# Usage: scripts/generate-sbom.sh <app> [out-root]
#   <app>       directory name under apps/ (python, node, go, java, rust)
#   [out-root]  default: sbom  -> files go to <out-root>/<app>/
# Env:
#   GENERATORS           space-separated subset of: syft trivy cdxgen native
#                        (default: all four)
#   IMAGE                image to scan (default: poc-<app>:local, must exist)
#   SBOM_SOURCE_VERSION  version recorded in the SBOM (default: git short SHA)
#   SBOM_SUPPLIER        supplier recorded in the SBOM
#
# Output in <out-root>/<app>/:
#   syft-{source,image}.{cdx,spdx}.json    Syft    (repo dir + built image)
#   trivy-{source,image}.{cdx,spdx}.json   Trivy   (repo dir + built image)
#   cdxgen-{source,image}.cdx.json         cdxgen  (repo dir + built image)
#   native-source.cdx.json                 the language's own OWASP CycloneDX
#                                          generator, run inside the Docker build
set -euo pipefail

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
APP_DIR="apps/$APP"
[[ -f "$APP_DIR/Dockerfile" ]] || { echo "error: $APP_DIR/Dockerfile not found" >&2; exit 1; }

GENERATORS="${GENERATORS:-syft trivy cdxgen native}"
IMAGE="${IMAGE:-poc-$APP:local}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb}"
CDXGEN_IMAGE="${CDXGEN_IMAGE:-poc-cdxgen:13.8.0}"   # built from tools/cdxgen (see its Dockerfile)
NAME="poc-$APP"
VERSION="${SBOM_SOURCE_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
SUPPLIER="${SBOM_SUPPLIER:-DevSecOps PoC}"

OUT="$OUT_ROOT/$APP"
CACHE="$OUT_ROOT/.cache/$APP"     # per app, so parallel runs never share a cache
mkdir -p "$OUT" "$CACHE/trivy"
OUT_ABS="$(cd "$OUT" && pwd)"
CACHE_ABS="$(cd "$CACHE" && pwd)"
SRC_ABS="$(cd "$APP_DIR" && pwd)"

log() { echo "==> [$APP] $*"; }
has_stage() { grep -qiE "^FROM .* AS $1\$" "$APP_DIR/Dockerfile"; }

docker image inspect "$IMAGE" > /dev/null 2>&1 \
  || { echo "error: image $IMAGE not found (run: make build APP=$APP)" >&2; exit 1; }

# --- Java: resolve pom.xml offline --------------------------------------------
# If the Dockerfile has a `maven-repo` stage, export the Maven repository the
# build already resolved, and let every tool read it OFFLINE. Otherwise each tool
# downloads hundreds of POMs from Maven Central, which rate-limits (HTTP 429).
M2_MOUNT=()
if has_stage maven-repo; then
  log "Exporting Maven repository from the Docker build"
  rm -rf "$CACHE/m2" && mkdir -p "$CACHE/m2"
  docker build -q --target maven-repo --output "type=local,dest=$CACHE/m2" "$APP_DIR" > /dev/null
  M2_MOUNT=(-v "$CACHE_ABS/m2":/tmp/.m2/repository)
fi

# Run a tool container as the current user in the docker group: output files are
# not root-owned, and tools can still read the Docker socket to find local images.
# label=disable: needed on SELinux hosts (Fedora) for the socket and bind mounts.
run_tool() {
  docker run --rm --security-opt label=disable \
    --user "$(id -u):$(stat -c '%g' /var/run/docker.sock)" \
    --tmpfs /tmp:mode=1777 -e HOME=/tmp \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$SRC_ABS":/src:ro -v "$OUT_ABS":/out -v "$CACHE_ABS":/cache "${M2_MOUNT[@]}" \
    "$@"
}

# Build output and installed deps are not "source"; skip them in source scans.
SKIP_DIRS=(node_modules target)

# --- Syft -----------------------------------------------------------------------
# --enrich (source only): look up missing licences online (PyPI, npm, Go proxy);
#   a source scan has no installed metadata. Images already carry licences, so
#   enriching them only costs time (55s for node). Java is not enriched: it would
#   query Maven Central; it reads the local Maven repo instead.
# --source-*: name/version/supplier in the SBOM metadata (NTIA minimum elements)
gen_syft() {
  local common=(--source-name "$NAME" --source-version "$VERSION" --source-supplier "$SUPPLIER")
  local excludes=() env=()
  for d in "${SKIP_DIRS[@]}"; do excludes+=(--exclude "./$d/**"); done
  if (( ${#M2_MOUNT[@]} )); then
    # Not enabled: SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=true. Measured on this
    # app it reported 262 packages (incl. test/optional deps of log4j) vs 31 shipped.
    env=(-e SYFT_JAVA_USE_NETWORK=false -e SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY=true
         -e SYFT_JAVA_MAVEN_LOCAL_REPOSITORY_DIR=/tmp/.m2/repository)
  fi

  log "Syft: source"
  run_tool "${env[@]}" "$SYFT_IMAGE" scan -q dir:/src "${common[@]}" "${excludes[@]}" \
    --enrich python --enrich javascript --enrich golang \
    -o cyclonedx-json=/out/syft-source.cdx.json -o spdx-json=/out/syft-source.spdx.json

  log "Syft: image"
  run_tool "$SYFT_IMAGE" scan -q "docker:$IMAGE" "${common[@]}" \
    -o cyclonedx-json=/out/syft-image.cdx.json -o spdx-json=/out/syft-image.spdx.json
}

# --- Trivy ----------------------------------------------------------------------
# --cache-dir: persistent per-app cache. Trivy downloads its Java DB (hundreds of
#   MB) to identify JARs; with a throwaway cache that happened on every run
#   (~190s per scan for java).
# --file-patterns: also read requirements-*.txt (by default Trivy only parses
#   files named exactly requirements.txt)
# One scan per format: `trivy convert` would halve the scans but drops package
# hashes, and with the cache in place the second scan takes a few seconds.
gen_trivy() {
  local skip=() src_flags=()
  for d in "${SKIP_DIRS[@]}"; do skip+=(--skip-dirs "/src/$d"); done
  (( ${#M2_MOUNT[@]} )) && src_flags=(--offline-scan)

  for fmt in cyclonedx:cdx spdx-json:spdx; do
    local format="${fmt%%:*}" ext="${fmt##*:}"
    log "Trivy: source ($format)"
    run_tool "$TRIVY_IMAGE" -q --cache-dir /cache/trivy fs "${skip[@]}" "${src_flags[@]}" \
      --file-patterns 'pip:requirements.*\.txt' \
      --format "$format" -o "/out/trivy-source.$ext.json" /src
    log "Trivy: image ($format)"
    run_tool "$TRIVY_IMAGE" -q --cache-dir /cache/trivy image --image-src docker \
      --format "$format" -o "/out/trivy-image.$ext.json" "$IMAGE"
  done
}

# --- cdxgen (OWASP CycloneDX) -----------------------------------------------------
# Polyglot generator that drives each ecosystem's own tooling (pip, npm, go, mvn,
# cargo). Built from npm in tools/cdxgen (the official image needs an AVX2 CPU).
#   source: runs INSIDE the app's own build image (Dockerfile `base` stage), with
#           node + cdxgen mounted in, so the real toolchain resolves dependencies;
#           on a scratch copy of the app, because cdxgen may write lock/temp files
#   image:  scans a `docker save` tarball of the built image
gen_cdxgen() {
  local shared="$OUT_ROOT/.cache/cdxgen-runtime"
  (
    flock 9   # parallel runs (make -j) build/export the tool only once
    docker build -q --target tool -t "$CDXGEN_IMAGE" tools/cdxgen > /dev/null
    if [[ ! -x "$shared/bin/node" ]]; then
      log "cdxgen: exporting node + cdxgen runtime"
      docker build -q --target runtime --output "type=local,dest=$shared" tools/cdxgen > /dev/null
    fi
  ) 9> "$OUT_ROOT/.cache/cdxgen.lock"

  local work="$CACHE_ABS/cdxgen-src"
  rm -rf "$work" && mkdir -p "$work"
  tar -C "$SRC_ABS" --exclude=node_modules --exclude=target -cf - . | tar -C "$work" -xf -

  local env=(-e CDXGEN_NO_BANNER=true -e FETCH_LICENSE=true
             -e GOPATH=/tmp/go -e GOCACHE=/tmp/gocache -e CARGO_HOME=/tmp/cargo)
  # Java: run Maven offline against the exported repo, with the CycloneDX plugin
  # version the native stage already put there.
  (( ${#M2_MOUNT[@]} )) && env+=(-e "MVN_ARGS=-o -Dmaven.repo.local=/tmp/.m2/repository"
                                  -e CDX_MAVEN_PLUGIN=org.cyclonedx:cyclonedx-maven-plugin:2.9.3)

  log "cdxgen: source (inside the app's build image)"
  docker build -q --target base -t "poc-$APP:base" "$APP_DIR" > /dev/null
  run_tool "${env[@]}" -v "$(cd "$shared" && pwd)":/opt/cdxgen:ro -v "$work":/work -w /work \
    --entrypoint /opt/cdxgen/bin/node "poc-$APP:base" \
    /opt/cdxgen/lib/node_modules/@cdxgen/cdxgen/bin/cdxgen.js \
    -r /work --no-install-deps --spec-version 1.6 \
    --project-name "$NAME" --project-version "$VERSION" \
    -o /out/cdxgen-source.cdx.json > "$CACHE_ABS/cdxgen-source.log" 2>&1 \
    || { tail -20 "$CACHE_ABS/cdxgen-source.log" >&2; return 1; }

  log "cdxgen: image"
  docker save -o "$CACHE_ABS/image.tar" "$IMAGE"
  run_tool "${env[@]}" "$CDXGEN_IMAGE" -t docker /cache/image.tar --spec-version 1.6 \
    --project-name "$NAME" --project-version "$VERSION" \
    -o /out/cdxgen-image.cdx.json > "$CACHE_ABS/cdxgen-image.log" 2>&1 \
    || { tail -20 "$CACHE_ABS/cdxgen-image.log" >&2; return 1; }
  rm -f "$CACHE_ABS/image.tar"
}

# --- Native (language's own OWASP CycloneDX generator) -----------------------------
# Runs inside the app's Docker build (`sbom` stage), with the real package
# manager and the real dependency resolution; exported via `sbom-export`.
gen_native() {
  has_stage sbom-export || { log "native: no sbom-export stage, skipped"; return 0; }
  log "native: $(grep -oE 'cyclonedx-[a-z]+|cargo-cyclonedx|cyclonedx-py' "$APP_DIR/Dockerfile" | head -1)"
  docker build -q --target sbom-export --output "type=local,dest=$OUT" "$APP_DIR" > /dev/null
}

for g in $GENERATORS; do
  declare -F "gen_$g" > /dev/null || { echo "error: unknown generator '$g'" >&2; exit 1; }
  "gen_$g"
done

log "Done: $(find "$OUT_ABS" -maxdepth 1 -name '*.json' | wc -l) files in $OUT"
