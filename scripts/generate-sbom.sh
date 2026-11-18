#!/usr/bin/env bash
# Generates SBOMs for one app with several generators. Every tool runs as a
# pinned container, a checksum-pinned binary, or inside the app's own Docker
# build, so local runs and CI behave the same.
#
# Security: no tool gets the Docker socket. Images are scanned from a
# `docker save` tarball; cdxgen's image scan runs with no network.
#
# Usage: scripts/generate-sbom.sh <app> [out-root]
#   <app>       directory name under apps/ (python, node, go, java, rust)
#   [out-root]  default: sbom  -> files go to <out-root>/<app>/
# Env:
#   STEP_TIMEOUT         seconds per tool call before it is killed (default: 600)
#   GENERATORS           space-separated subset of: syft trivy cdxgen native
#                        (default: all four)
#   IMAGE                image to scan (default: poc-<app>:local, from
#                        scripts/build-image.sh, which also records its digest)
#   SBOM_SOURCE_VERSION  version recorded in the SBOM (default: git short SHA)
#   SBOM_SUPPLIER        supplier recorded in the SBOM
#
# Output in <out-root>/<app>/ (stage in the name; see docs/SBOM-TYPES.md):
#   <gen>-source.*   Source SBOM  (CISA "Source",   CycloneDX lifecycle pre-build)
#   native-build.*   Build SBOM   (CISA "Build",    lifecycle build): the language's
#                    own OWASP CycloneDX generator, run inside the Docker build
#   <gen>-image.*    Analyzed SBOM (CISA "Analyzed", lifecycle post-build)
# Formats: .cdx.json = CycloneDX (1.7 where the tool supports it),
#          .spdx.json = SPDX 2.3, .spdx3.json = SPDX 3.0.1 (Syft, cdxgen)
#   syft-{source,image}.{cdx,spdx,spdx3}.json
#   trivy-{source,image}.{cdx,spdx}.json      (Trivy has no SPDX 3 output)
#   cdxgen-{source,image}.{cdx,spdx3}.json
#   native-build.cdx.json
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
APP_DIR="apps/$APP"
[[ -f "$APP_DIR/Dockerfile" ]] || { echo "error: $APP_DIR/Dockerfile not found" >&2; exit 1; }

GENERATORS="${GENERATORS:-syft trivy cdxgen native}"
IMAGE="${IMAGE:-poc-$APP:local}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb}"
# cdxgen standalone release binary (static, Node built in); checksum from the release's .sha256
CDXGEN_VERSION="${CDXGEN_VERSION:-v13.8.0}"
CDXGEN_SHA256="${CDXGEN_SHA256:-01f2a7f822449242987942ae81da7464dc9d8eed27ae36d33b0f4ddce95e5b43}"
# Pinned glibc image with libatomic: runs cdxgen's image scan (sandboxed), and
# provides libatomic.so.1 for source scans in slim app images.
CDXGEN_RUNNER_IMAGE="rust:1-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37"
STEP_TIMEOUT="${STEP_TIMEOUT:-600}"   # seconds per tool call; a hang fails fast and names itself
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
source "$(dirname "$0")/buildkit.sh"   # bk_ensure / bk_build: the shared builder
has_stage() { grep -qiE "^FROM .* AS $1\$" "$APP_DIR/Dockerfile"; }

# step <name> <command...>: runs with a timeout, sends output to
# $CACHE/<name>.log, prints the duration, and shows the log tail on failure.
step() {
  local name="$1"; shift
  local logf="$CACHE_ABS/$name.log" start=$SECONDS rc=0
  log "$name ..."
  # `timeout` can only run programs, so the helper functions and the variables
  # they use are handed to a child bash that timeout can kill.
  local state
  # (`|| true`: helpers defined later in the script don't exist yet for early steps)
  state="$({ declare -p APP APP_DIR OUT_ROOT OUT_ABS CACHE_ABS SRC_ABS M2_MOUNT \
                        CDXGEN_VERSION CDXGEN_SHA256 CDXGEN_RUNNER_IMAGE
             declare -p BK_REGISTRY BK_BUILDER
           declare -f log run_tool export_stage fetch_cdxgen bk_build; } 2> /dev/null || true)"
  timeout --kill-after=30 "$STEP_TIMEOUT" \
    bash -c "$state"$'\n''"$@"' _ "$@" > "$logf" 2>&1 || rc=$?
  if (( rc != 0 )); then
    (( rc == 124 )) && echo "TIMEOUT [$APP] $name after ${STEP_TIMEOUT}s" >&2
    echo "FAIL [$APP] $name (exit $rc). Last lines of $logf:" >&2
    tail -30 "$logf" >&2
    return "$rc"
  fi
  log "$name ok ($((SECONDS - start))s)"
}

# export_stage <stage> <path-in-stage> <dest-dir>: builds a Dockerfile stage on the
# shared BuildKit builder (reusing the layers the test/runtime builds already made),
# pulls it through the local registry and copies files out with `docker create` +
# `docker cp`. Deliberately not `--output type=local`: that hung on GitHub runners.
export_stage() {
  local stage="$1" path="$2" dest="$3" tag="poc-$APP:$1" cid
  bk_build "$APP" "$stage" --pull-as "$tag" || return
  cid=$(docker create "$tag" /none) || return
  mkdir -p "$dest"
  docker cp "$cid:$path" "$dest"; local rc=$?
  docker rm "$cid" > /dev/null
  return "$rc"
}

bk_ensure "$OUT_ROOT"
docker image inspect "$IMAGE" > /dev/null 2>&1 \
  || { echo "error: image $IMAGE not found (run: make build APP=$APP)" >&2; exit 1; }

# --- Java: resolve pom.xml offline --------------------------------------------
# If the Dockerfile has a `maven-repo` stage, export the Maven repository the
# build already resolved, and let every tool read it OFFLINE. Otherwise each tool
# downloads hundreds of POMs from Maven Central, which rate-limits (HTTP 429).
M2_MOUNT=()
if has_stage maven-repo; then
  rm -rf "$CACHE/m2"
  step maven-repo export_stage maven-repo /. "$CACHE/m2"
  M2_MOUNT=(-v "$CACHE_ABS/m2":/tmp/.m2/repository)
fi

# Run a tool container as the current user (output files are not root-owned).
# No Docker socket: images are scanned from /cache/image.tar instead.
# label=disable: needed on SELinux hosts (Fedora) for the bind mounts.
run_tool() {
  docker run --rm --security-opt label=disable \
    --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:mode=1777,exec,size=4g -e HOME=/tmp \
    -v "$SRC_ABS":/src:ro -v "$OUT_ABS":/out -v "$CACHE_ABS":/cache "${M2_MOUNT[@]}" \
    "$@"
}

# The image every image scan reads: saved once, removed on exit
IMAGE_TAR="$CACHE_ABS/image.tar"
trap 'rm -f "$IMAGE_TAR"' EXIT
if [[ " $GENERATORS " =~ \ (syft|trivy|cdxgen)\  ]]; then
  step image-save docker save -o "$IMAGE_TAR" "$IMAGE"
fi

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

  step syft-source run_tool "${env[@]}" "$SYFT_IMAGE" scan -v dir:/src "${common[@]}" "${excludes[@]}" \
    --enrich python --enrich javascript --enrich golang \
    -o cyclonedx-json=/out/syft-source.cdx.json -o spdx-json=/out/syft-source.spdx.json \
    -o spdx-json@3.0=/out/syft-source.spdx3.json

  # File digests: SHA-1 (SPDX 2.3 requires it for files) and SHA-512 (BSI
  # TR-03183-2 requires SHA-512 for deployable components), besides SHA-256.
  # (comma-separated: with spaces Syft keeps only SHA-1 and its SPDX 2.3 turns invalid)
  step syft-image run_tool -e SYFT_FILE_METADATA_DIGESTS=sha1,sha256,sha512 \
    "$SYFT_IMAGE" scan -v docker-archive:/cache/image.tar "${common[@]}" \
    -o cyclonedx-json=/out/syft-image.cdx.json -o spdx-json=/out/syft-image.spdx.json \
    -o spdx-json@3.0=/out/syft-image.spdx3.json \
    -o syft-json=/cache/syft-image.syft.json   # file ownership, used by runtime-sbom.sh
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
    step "trivy-source-$ext" run_tool "$TRIVY_IMAGE" --cache-dir /cache/trivy fs --no-progress "${skip[@]}" "${src_flags[@]}" \
      --file-patterns 'pip:requirements.*\.txt' \
      --format "$format" -o "/out/trivy-source.$ext.json" /src
    step "trivy-image-$ext" run_tool "$TRIVY_IMAGE" --cache-dir /cache/trivy image --no-progress \
      --input /cache/image.tar --format "$format" -o "/out/trivy-image.$ext.json"
  done
}

# --- cdxgen (OWASP CycloneDX) -----------------------------------------------------
# Polyglot generator that drives each ecosystem's own tooling (pip, npm, go, mvn,
# cargo). Uses the standalone release binary, the method cdxgen's README
# recommends for CI: 183 MB, statically linked, no image to build. (The official
# image is ~16.6 GB and needs an x86-64-v3/AVX2 CPU.)
#   source: runs INSIDE the app's own build image (Dockerfile `base` stage), with
#           the binary mounted in, so the real toolchain resolves dependencies;
#           on a scratch copy of the app, because cdxgen may write lock/temp files
#   image:  runs the binary on the `docker save` tarball, in a pinned container
#           with NO network and no socket (it never needs either)
# Licences are not fetched online (FETCH_LICENSE): slow and rate-limited, and the
# other generators already provide licences.
CDXGEN_BIN=""
fetch_cdxgen() {
  local dir="$OUT_ROOT/.cache/cdxgen-$CDXGEN_VERSION" asset="cdxgen-linux-amd64"
  mkdir -p "$dir"
  (
    flock 9   # parallel runs (make -j) download only once
    if ! echo "$CDXGEN_SHA256  $dir/$asset" | sha256sum -c --status 2> /dev/null; then
      curl -fsSL --retry 3 -o "$dir/$asset.tmp" \
        "https://github.com/cdxgen/cdxgen/releases/download/$CDXGEN_VERSION/$asset"
      echo "$CDXGEN_SHA256  $dir/$asset.tmp" | sha256sum -c --status \
        || { echo "error: cdxgen checksum mismatch" >&2; rm -f "$dir/$asset.tmp"; exit 1; }
      mv "$dir/$asset.tmp" "$dir/$asset" && chmod +x "$dir/$asset"
    fi
    # The binary's embedded Node needs libatomic.so.1, which slim images
    # (python, node, java) lack. Ship it next to the binary instead of changing
    # the app images (that would change their SBOMs). Taken from the pinned Rust
    # build image; `cat` follows the symlink to the real file.
    if [[ ! -s "$dir/lib/libatomic.so.1" ]]; then
      mkdir -p "$dir/lib"
      docker run --rm --entrypoint cat "$CDXGEN_RUNNER_IMAGE" \
        /lib/x86_64-linux-gnu/libatomic.so.1 > "$dir/lib/libatomic.so.1"
    fi
  ) 9> "$dir/.lock"
  CDXGEN_BIN="$(cd "$dir" && pwd)/$asset"
}

gen_cdxgen() {
  step cdxgen-download fetch_cdxgen
  [[ -n "$CDXGEN_BIN" ]] || CDXGEN_BIN="$(cd "$OUT_ROOT/.cache/cdxgen-$CDXGEN_VERSION" && pwd)/cdxgen-linux-amd64"

  local work="$CACHE_ABS/cdxgen-src"
  rm -rf "$work" && mkdir -p "$work"
  tar -C "$SRC_ABS" --exclude=node_modules --exclude=target -cf - . | tar -C "$work" -xf -

  local env=(-e CDXGEN_NO_BANNER=true -e FETCH_LICENSE=false
             -e GOPATH=/tmp/go -e GOCACHE=/tmp/gocache -e CARGO_HOME=/tmp/cargo)
  # Java: run Maven offline against the exported repo, with the CycloneDX plugin
  # version the native stage already put there.
  (( ${#M2_MOUNT[@]} )) && env+=(-e "MVN_ARGS=-o -Dmaven.repo.local=/tmp/.m2/repository"
                                  -e CDX_MAVEN_PLUGIN=org.cyclonedx:cyclonedx-maven-plugin:2.9.3)

  step cdxgen-base-image bk_build "$APP" base --pull-as "poc-$APP:base"
  local libdir; libdir="$(dirname "$CDXGEN_BIN")/lib"
  # --no-install-deps keeps cdxgen from running pip/npm/cargo installs. For Java it
  # would also skip Maven ("only the direct dependencies declared in pom.xml");
  # Maven runs offline here (MVN_ARGS -o), so it's allowed.
  local install=(--no-install-deps)
  (( ${#M2_MOUNT[@]} )) && install=()
  step cdxgen-source run_tool "${env[@]}" -v "$CDXGEN_BIN":/usr/local/bin/cdxgen:ro \
    -v "$libdir":/opt/cdxgen-lib:ro -e LD_LIBRARY_PATH=/opt/cdxgen-lib \
    -v "$work":/work -w /work --entrypoint /usr/local/bin/cdxgen "poc-$APP:base" \
    -r /work "${install[@]}" --spec-version 1.7 --format cyclonedx,spdx \
    --project-name "$NAME" --project-version "$VERSION" -o /out/cdxgen-source.cdx.json

  step cdxgen-image run_tool --network none -e CDXGEN_NO_BANNER=true -e FETCH_LICENSE=false -e SEARCH_MAVEN_ORG=false \
    -v "$CDXGEN_BIN":/usr/local/bin/cdxgen:ro --entrypoint /usr/local/bin/cdxgen \
    "$CDXGEN_RUNNER_IMAGE" -t docker /cache/image.tar --spec-version 1.7 --format cyclonedx,spdx \
    --project-name "$NAME" --project-version "$VERSION" -o /out/cdxgen-image.cdx.json
  # --format spdx writes SPDX 3.0.1 next to the CycloneDX file; the name depends
  # on the -o name (x.cdx.json -> x.spdx.json; x.json -> x.spdx.json). Rename it
  # to *.spdx3.json so it can't be mistaken for an SPDX 2.3 file.
  local t f
  for t in source image; do
    for f in "$OUT_ABS/cdxgen-$t.spdx.json" "$OUT_ABS/cdxgen-$t.cdx.spdx.json"; do
      [[ -s "$f" ]] && mv -f "$f" "$OUT_ABS/cdxgen-$t.spdx3.json"
    done
    [[ -s "$OUT_ABS/cdxgen-$t.spdx3.json" ]] || { echo "FAIL [$APP] cdxgen wrote no SPDX 3 file ($t)" >&2; return 1; }
  done
}

# --- Native (language's own OWASP CycloneDX generator) -----------------------------
# Runs inside the app's Docker build (`sbom` stage), with the real package
# manager and the real dependency resolution; exported via `sbom-export`.
gen_native() {
  has_stage sbom-export || { log "native: no sbom-export stage, skipped"; return 0; }
  step native export_stage sbom-export /native-build.cdx.json "$OUT_ABS"
}

for g in $GENERATORS; do
  declare -F "gen_$g" > /dev/null || { echo "error: unknown generator '$g'" >&2; exit 1; }
  "gen_$g"
done

bash "$(dirname "$0")/label-lifecycle.sh" "$APP" "$OUT_ROOT"
bash "$(dirname "$0")/make-views.sh" "$APP" "$OUT_ROOT"
log "Done: $(find "$OUT_ABS" -maxdepth 1 -name '*.json' | wc -l) files in $OUT"
