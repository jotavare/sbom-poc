#!/usr/bin/env bash
# Sanity-checks the SBOMs of one app (from scripts/generate-sbom.sh).
#
# Usage: scripts/check-sbom.sh <app> [out-root]
# Env:   GENERATORS (same as generate-sbom.sh; default: syft trivy cdxgen native)
#
# Every CycloneDX SBOM must contain each package URL listed in
# apps/<app>/sbom-expect.txt (the app's deliberately vulnerable pins).
set -euo pipefail

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
EXPECT="apps/$APP/sbom-expect.txt"
GENERATORS="${GENERATORS:-syft trivy cdxgen native}"
fail() { echo "FAIL [$APP]: $*" >&2; exit 1; }

[[ -s "$EXPECT" ]] || fail "missing $EXPECT"

# Files each generator must have produced
expected_files() {
  case "$1" in
    syft|trivy) echo "$1-source.cdx.json $1-source.spdx.json $1-image.cdx.json $1-image.spdx.json" ;;
    cdxgen)     echo "cdxgen-source.cdx.json cdxgen-image.cdx.json" ;;
    native)     grep -qiE '^FROM .* AS sbom-export$' "apps/$APP/Dockerfile" && echo "native-source.cdx.json" ;;
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
    | sed -E 's/[?#].*$//' | tr '[:upper:]' '[:lower:]' | sort -u
}

for f in "$DIR"/*.cdx.json; do
  jq -e '[.components[]? | select(.type == "library")] | length > 0' "$f" > /dev/null \
    || fail "$f has no libraries"
  found=$(purls "$f")
  while read -r want; do
    [[ -z "$want" || "$want" == \#* ]] && continue
    grep -qxF "$(tr '[:upper:]' '[:lower:]' <<< "$want")" <<< "$found" \
      || fail "$want not found in $f"
  done < "$EXPECT"
done

for f in "$DIR"/*.spdx.json; do
  [[ -e "$f" ]] || continue
  jq -e '.packages | length > 0' "$f" > /dev/null || fail "$f has no packages"
done

# Image SBOMs must include OS packages (deb/apk/rpm), even for distroless images
for f in "$DIR"/*-image.cdx.json; do
  [[ -e "$f" ]] || continue
  jq -e '[.. | objects | select(has("purl")) | .purl // "" | select(test("^pkg:(deb|apk|rpm)/"))] | length > 0' \
    "$f" > /dev/null || fail "no OS packages in $(basename "$f")"
done

echo "OK [$APP]: all SBOM checks passed ($(find "$DIR" -maxdepth 1 -name '*.json' | wc -l) files)"
