#!/usr/bin/env bash
# Writes one app's report, organised by SBOM stage (see docs/SBOM-TYPES.md):
#   overview -> 1 source -> 2 build -> 3 post-build (image) -> 4 runtime
#   -> cross-cutting checks (validation, licences, quality, ScanCode)
# Sections whose inputs don't exist yet (e.g. runtime before `make runtime`) say so.
#
# Usage: scripts/summary.sh <app> [out-root]    (Markdown to stdout)
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
ROOT="${2:-sbom}"
DIR="$ROOT/$APP"
HERE="$(dirname "$0")"
R="$DIR/reports"

section() { [[ -s "$1" ]] && cat "$1" || { echo "_Not generated yet: run \`make $2 APP=$APP\`._"; echo; }; }
demote() { sed -E 's/^## /#### /'; }   # tool reports use "##"; nest them under the stage headings

echo "# $APP"
echo

# --- overview ------------------------------------------------------------------------
echo "### Overview: every SBOM of this app"
echo
echo "| Stage (CISA type / CycloneDX lifecycle) | File | Generator | Format | Packages |"
echo "|---|---|---|---|---|"
shopt -s nullglob
for f in "$DIR"/*.cdx.json "$DIR"/*.spdx.json "$DIR"/*.spdx3.json; do
  b="$(basename "$f")"
  case "$b" in
    *-source.*)       key=1; stage="1 Source / pre-build" ;;
    native-build.*)   key=2; stage="2 Build / build" ;;
    buildkit-image.*) key=3; stage="2 Build (image attestation)" ;;
    *-image.*)        key=4; stage="3 Analyzed / post-build" ;;
    runtime.*)        key=5; stage="4 Runtime / operations" ;;
    *)                key=9; stage="?" ;;
  esac
  gen="${b%%-*}"; [[ "$b" == runtime.* ]] && gen="strace + Syft"
  case "$b" in
    *.cdx.json)   fmt="CycloneDX $(jq -r .specVersion "$f")"
                  n=$(jq '[.. | objects | select((.type? == "library" or .type? == "framework") and has("bom-ref"))] | length' "$f") ;;
    *.spdx3.json) fmt="SPDX 3.0.1"
                  n=$(jq '[.["@graph"][]? | select(.type == "software_Package")] | length' "$f") ;;
    *.spdx.json)  fmt="$(jq -r .spdxVersion "$f")"; n=$(jq '.packages | length' "$f") ;;
  esac
  printf '%s\t| %s | `%s` | %s | %s | %s |\n' "$key$b" "$stage" "$b" "$gen" "$fmt" "$n"
done | sort | cut -f2-
echo
if [[ -s "$DIR/artifact.json" ]]; then
  echo "Image: \`$(jq -r '.image + "@" + .index_digest' "$DIR/artifact.json")\` (commit \`$(jq -r '.commit[0:12]' "$DIR/artifact.json")\`)"
  echo
fi

# --- 1 source --------------------------------------------------------------------------
echo "### 1. Source (pre-build): what the repository declares"
echo
NO_APP_HEADING=1 COMPARE_TARGETS=source SBOM_ROOT="$ROOT" bash "$HERE/compare-sbom.sh" "$APP" | demote

# --- 2 build ---------------------------------------------------------------------------
echo "### 2. Build: what the build resolved and produced"
echo
echo "- **native-build**: the package manager's own SBOM, generated inside the Docker build (compared with the source SBOMs above; its dependency tree is the reference)."
if [[ -s "$DIR/buildkit-provenance.json" ]]; then
  echo "- **BuildKit attestation**: SBOM + SLSA provenance attached to the image in the registry. Provenance build type: \`$(jq -r '.buildDefinition.buildType // "?"' "$DIR/buildkit-provenance.json")\`; resolved build inputs: $(jq '[.buildDefinition.resolvedDependencies[]?] | length' "$DIR/buildkit-provenance.json")."
fi
echo

# --- 3 post-build ------------------------------------------------------------------------
echo "### 3. Post-build (analyzed): what is in the image"
echo
NO_APP_HEADING=1 COMPARE_TARGETS=image SBOM_ROOT="$ROOT" bash "$HERE/compare-sbom.sh" "$APP" | demote
if compgen -G "$DIR/views/*-image-app.cdx.json" > /dev/null; then
  echo "**OS / app views** (packages per view)"
  echo
  echo "| Generator | OS packages | App packages |"
  echo "|---|---|---|"
  for f in "$DIR"/views/*-image-os.cdx.json; do
    g="$(basename "$f" -image-os.cdx.json)"
    echo "| $g | $(jq '.components | length' "$f") | $(jq '.components | length' "$DIR/views/$g-image-app.cdx.json") |"
  done
  echo
fi
section "$R/unmanaged.md" unmanaged | demote

# --- 4 runtime ---------------------------------------------------------------------------
echo "### 4. Runtime (operations): what actually runs"
echo
section "$R/runtime.md" runtime | demote

# --- cross-cutting -----------------------------------------------------------------------
echo "### Checks across all stages"
echo
section "$R/validation.md" validate | demote
bash "$HERE/check-licenses.sh" "$APP" "$ROOT" | demote
bash "$HERE/score-sbom.sh" "$APP" "$ROOT" | demote
if [[ -s "$R/scancode.md" ]]; then demote < "$R/scancode.md"
else echo "#### ScanCode"; echo; echo "_One-off scan, not run for this report (\`make scancode APP=$APP\` or the ScanCode workflow)._"; echo; fi
