#!/usr/bin/env bash
# Compares the CycloneDX SBOMs of every generator side by side (Markdown to stdout).
#
# Usage: scripts/compare-sbom.sh [app...]     (no args = every app with SBOMs)
# Env:   SBOM_ROOT (default: sbom), MAX_DIFF_ROWS (default: 40)
set -euo pipefail

ROOT="${SBOM_ROOT:-sbom}"
GEN_ORDER=(syft trivy cdxgen native)
MAX_DIFF_ROWS="${MAX_DIFF_ROWS:-40}"

if (( $# == 0 )); then
  mapfile -t APPS < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -not -name '.*' -printf '%f\n' | sort)
else
  APPS=("$@")
fi
(( ${#APPS[@]} > 0 )) || { echo "error: no SBOMs under $ROOT/ (run make sbom first)" >&2; exit 1; }

# All library components, wherever they are nested (cdxgen nests some)
LIBS='[.. | objects | select((.type? == "library" or .type? == "framework") and has("bom-ref"))]'

# label|jq expression over a CycloneDX document
METRICS=(
  "Libraries (total)|$LIBS | length"
  "  dev/test (not compared)|$LIBS | map(select((.scope // \"required\") != \"required\")) | length"
  "  OS source pkgs (not compared)|$LIBS | map(select((.purl // \"\") | test(\"[?&]arch=source\"))) | length"
  "with licence|$LIBS | map(select((.licenses // []) | length > 0)) | length"
  "with hashes|$LIBS | map(select((.hashes // []) | length > 0)) | length"
  "with CPE|$LIBS | map(select(.cpe)) | length"
  "with PURL|$LIBS | map(select(.purl)) | length"
  "File entries|[.components[]? | select(.type == \"file\")] | length"
  "Dependency edges|[(.dependencies // [])[] | (.dependsOn // [])[]] | length"
  "Supplier set|if (.metadata.component.supplier.name // .metadata.supplier.name) then \"yes\" else \"no\" end"
  "CycloneDX spec|.specVersion"
)

# Package-URL types of the library components, e.g. "pypi", "deb", "golang"
purl_types() { jq -r "$LIBS | .[] | .purl // empty | capture(\"^pkg:(?<t>[^/]+)/\").t" "$1"; }

# Components that are not compared (counted in their own rows instead):
#   - dev/test dependencies: cdxgen lists them with scope "optional"/"excluded";
#     the other generators leave them out (its "required" set matches native)
#   - Debian source packages: cdxgen adds e.g. glibc (?arch=source) next to the
#     binary packages (libc6) that every tool lists
#   - the app itself (poc-*, the Go module), which some tools list as a component
IN_SCOPE='select((.scope // "required") == "required")
          | select((.purl // "") | test("[?&]arch=source") | not)
          | select((.purl // "") | test("/poc-[a-z]+@|/poc-[a-z]+$|devsecops-sbom-poc") | not)'

# Normalised "type/name@version" packages, so representation differences don't
# look like different packages:
#   - qualifiers (?arch=, ?epoch=, ...) and #subpath dropped; lower-cased
#   - Debian epochs: in the version (1:2.41 or 1%3a2.41) vs ?epoch=1
#   - "+" vs "%2b" (e.g. Go +incompatible, Debian +deb13u1)
#   - Go: "v" prefixes (stdlib@v1.27.4) and std@go1.27.4 vs stdlib@1.27.4
#   - PyPI: names compared per PEP 503 (_ and . are the same as -)
#   - npm scopes: %40scope and @scope are the same
packages() {
  jq -r "$LIBS | .[] | $IN_SCOPE | .purl // empty" "$1" \
    | sed -E 's/[?#].*$//; s/^pkg://; s/%40/@/g; s/%2[bB]/+/g; s/@[0-9]+(%3[aA]|:)/@/' \
    | sed -E 's/^golang\/std@go/golang\/stdlib@/; s/^(golang\/[^@]+)@v/\1@/' \
    | tr '[:upper:]' '[:lower:]' \
    | awk -F'@' '/^pypi\// { n=$1; sub(/^pypi\//, "", n); gsub(/[_.]/, "-", n); print "pypi/" n "@" $2; next } { print }' \
    | sort -u
}

human_size() { numfmt --to=iec --suffix=B "$(stat -c%s "$1")"; }

compare_target() {
  local app="$1" target="$2" gens=() files=()
  for g in "${GEN_ORDER[@]}"; do
    local f="$ROOT/$app/$g-$target.cdx.json"
    [[ -s "$f" ]] && { gens+=("$g"); files+=("$f"); }
  done
  (( ${#gens[@]} > 0 )) || return 0

  echo "## ${target^} SBOM"
  echo
  printf '| Metric |'; printf ' %s |' "${gens[@]}"; echo
  printf '|---|'; printf -- '---|%.0s' "${gens[@]}"; echo
  local types; types=$(for f in "${files[@]}"; do purl_types "$f"; done | sort -u)
  for t in $types; do
    printf '| `pkg:%s` |' "$t"
    for f in "${files[@]}"; do printf ' %s |' "$(purl_types "$f" | grep -cxF "$t" || true)"; done; echo
  done
  for m in "${METRICS[@]}"; do
    printf '| %s |' "${m%%|*}"
    for f in "${files[@]}"; do printf ' %s |' "$(jq -r "${m#*|}" "$f")"; done; echo
  done
  printf '| File size |'; for f in "${files[@]}"; do printf ' %s |' "$(human_size "$f")"; done; echo
  echo
  (( ${#gens[@]} > 1 )) || return 0

  # Which generator found which package (only packages not found by all)
  local tmp; tmp=$(mktemp -d)
  for i in "${!gens[@]}"; do packages "${files[$i]}" > "$tmp/${gens[$i]}"; done
  sort -u "$tmp"/* > "$tmp/all"
  local rows=()
  while read -r pkg; do
    local row="| \`$pkg\` |" found=0
    for g in "${gens[@]}"; do
      if grep -qxF "$pkg" "$tmp/$g"; then row+=" ✓ |"; found=$((found + 1)); else row+=" · |"; fi
    done
    (( found < ${#gens[@]} )) && rows+=("$row")
  done < "$tmp/all"
  local total; total=$(wc -l < "$tmp/all")
  echo "**Agreement:** $((total - ${#rows[@]})) of $total packages found by every generator (runtime dependencies, after normalisation)."
  echo
  if (( ${#rows[@]} > 0 )); then
    echo "<details><summary>${#rows[@]} packages not found by every generator</summary>"
    echo
    printf '| Package |'; printf ' %s |' "${gens[@]}"; echo
    printf '|---|'; printf -- '---|%.0s' "${gens[@]}"; echo
    printf '%s\n' "${rows[@]:0:$MAX_DIFF_ROWS}"
    (( ${#rows[@]} > MAX_DIFF_ROWS )) && echo "| … $(( ${#rows[@]} - MAX_DIFF_ROWS )) more | |"
    echo
    echo "</details>"
    echo
  fi
  rm -rf "$tmp"
}

for app in "${APPS[@]}"; do
  echo "# $app"
  echo
  compare_target "$app" source
  compare_target "$app" image
done
