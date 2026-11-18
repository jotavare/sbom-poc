#!/usr/bin/env bash
# Sanity-checks the SBOMs of one app (from build-image.sh + generate-sbom.sh).
#
# Usage: scripts/check-sbom.sh <app> [out-root]
# Env:   GENERATORS (same as generate-sbom.sh; default: syft trivy cdxgen native)
#
# Per app (apps/<app>/):
#   sbom-expect.txt       package URLs every CycloneDX SBOM MUST contain
#                         (the deliberately vulnerable pins)
#   sbom-reject.txt       packages that must NOT appear in what ships: the
#                         image SBOMs, their app views and the native SBOM
#                         (dev/test dependencies). Matched by type/name, any version.
#   sbom-expect-skip.txt  "<sbom file> <purl|*> <reason>": documented exceptions
#                         to sbom-expect.txt (a known generator limitation)
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
A="apps/$APP"
GENERATORS="${GENERATORS:-syft trivy cdxgen native}"
fail() { echo "FAIL [$APP]: $*" >&2; exit 1; }
lc() { tr '[:upper:]' '[:lower:]'; }

[[ -s "$A/sbom-expect.txt" ]] || fail "missing $A/sbom-expect.txt"

# --- the artifact and every expected file exist ------------------------------------
[[ -s "$DIR/artifact.json" ]] || fail "missing $DIR/artifact.json (run: make build APP=$APP)"
jq -e '.index_digest | startswith("sha256:")' "$DIR/artifact.json" > /dev/null \
  || fail "artifact.json has no image digest"
# every image SBOM must name this exact image in its generator's digest field
for f in "$DIR"/*-image.cdx.json; do
  field=$(jq -r --slurpfile a "$DIR/artifact.json" -L "$(dirname "$0")" 'include "image-binding"; binding($a[0]) // empty' "$f")
  [[ -n "$field" ]] || fail "$(basename "$f") is not bound to the image: none of its digest fields matches artifact.json"
done
[[ -s "$DIR/buildkit-image.spdx.json" ]] || fail "missing BuildKit SBOM attestation"

expected_files() {
  case "$1" in
    syft)       echo "syft-source.cdx.json syft-source.spdx.json syft-source.spdx3.json"
                echo "syft-image.cdx.json syft-image.spdx.json syft-image.spdx3.json" ;;
    trivy)      echo "trivy-source.cdx.json trivy-source.spdx.json trivy-image.cdx.json trivy-image.spdx.json" ;;
    cdxgen)     echo "cdxgen-source.cdx.json cdxgen-source.spdx3.json cdxgen-image.cdx.json cdxgen-image.spdx3.json" ;;
    native)     grep -qiE '^FROM .* AS sbom-export$' "$A/Dockerfile" && echo "native-build.cdx.json" ;;
    *)          fail "unknown generator '$1'" ;;
  esac
}
for g in $GENERATORS; do
  for f in $(expected_files "$g"); do
    [[ -s "$DIR/$f" ]] || fail "missing $DIR/$f"
  done
done

# Lower-cased package URLs without ?qualifiers or #subpath
purls() {
  jq -r '.. | objects | select(has("purl")) | .purl // empty' "$1" \
    | sed -E 's/[?#].*$//; s/%40/@/g; s/%2[bB]/+/g' | lc | sort -u
}

skip_reason() {  # <file> <purl> -> reason, if this marker is excused for this file
  [[ -f "$A/sbom-expect-skip.txt" ]] || return 1
  awk -v f="$1" -v p="$2" '$1 == f && ($2 == "*" || tolower($2) == p) { $1 = $2 = ""; sub(/^ +/, ""); print; exit }' \
    "$A/sbom-expect-skip.txt" | grep .
}

# --- positive markers --------------------------------------------------------------
for f in "$DIR"/*.cdx.json; do
  base="$(basename "$f")"
  jq -e '[.components[]? | select(.type == "library" or .type == "framework")] | length > 0' "$f" > /dev/null \
    || fail "$base has no libraries"
  found=$(purls "$f")
  while read -r want; do
    [[ -z "$want" || "$want" == \#* ]] && continue
    want=$(lc <<< "$want")
    grep -qxF "$want" <<< "$found" && continue
    if reason=$(skip_reason "$base" "$want"); then
      echo "SKIP [$APP]: $base lacks $want: $reason"
    else
      fail "$want not found in $base"
    fi
  done < "$A/sbom-expect.txt"
done

# --- negative markers: dev/test dependencies must not ship ------------------------------
if [[ -s "$A/sbom-reject.txt" ]]; then
  shopt -s nullglob
  for f in "$DIR"/*-image.cdx.json "$DIR"/views/*-image-app.cdx.json "$DIR"/native-build.cdx.json; do
    found=$(purls "$f" | sed -E 's/@[^@/]*$//')     # type/name, version dropped
    while read -r reject; do
      [[ -z "$reject" || "$reject" == \#* ]] && continue
      grep -qxF "$(lc <<< "$reject")" <<< "$found" \
        && fail "$reject must not appear in $(basename "$f") (dev/test dependency shipped)"
    done < "$A/sbom-reject.txt"
  done
fi

# --- every CycloneDX SBOM declares its stage (CISA "Generation Context") ---------------
for f in "$DIR"/*.cdx.json; do
  jq -e '(.metadata.lifecycles // []) | length > 0' "$f" > /dev/null \
    || fail "$(basename "$f") has no metadata.lifecycles (run scripts/label-lifecycle.sh)"
done

# --- SPDX files have packages; image SBOMs have OS packages (even distroless) ---------
for f in "$DIR"/*.spdx.json; do
  jq -e '.packages | length > 0' "$f" > /dev/null || fail "$(basename "$f") has no packages"
done
for f in "$DIR"/*.spdx3.json; do
  jq -e '[.["@graph"][]? | select(.type == "software_Package")] | length > 0' "$f" > /dev/null \
    || fail "$(basename "$f") has no software_Package elements"
done
for f in "$DIR"/*-image.cdx.json; do
  jq -e '[.. | objects | select(has("purl")) | .purl // "" | select(test("^pkg:(deb|apk|rpm)/"))] | length > 0' \
    "$f" > /dev/null || fail "no OS packages in $(basename "$f")"
done

echo "OK [$APP]: all SBOM checks passed ($(find "$DIR" -maxdepth 1 -name '*.json' | wc -l) files, image $(jq -r '.index_digest[0:19]' "$DIR/artifact.json"))"
