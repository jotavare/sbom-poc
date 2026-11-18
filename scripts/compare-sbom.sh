#!/usr/bin/env bash
# Compares the SBOMs of every generator side by side (Markdown to stdout).
# CycloneDX SBOMs from Syft, Trivy, cdxgen and the native generators; for the
# image, also BuildKit's SPDX attestation (mapped to the same shape here).
#
# Usage: scripts/compare-sbom.sh [app...]     (no args = every app with SBOMs)
# Env:   SBOM_ROOT (default: sbom), MAX_DIFF_ROWS (default: 40)
set -euo pipefail
export LC_ALL=C

ROOT="${SBOM_ROOT:-sbom}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GEN_ORDER=(syft trivy cdxgen native)
MAX_DIFF_ROWS="${MAX_DIFF_ROWS:-40}"

if (( $# == 0 )); then
  mapfile -t APPS < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -not -name '.*' -printf '%f\n' | sort)
else
  APPS=("$@")
fi
(( ${#APPS[@]} > 0 )) || { echo "error: no SBOMs under $ROOT/ (run make sbom first)" >&2; exit 1; }

# All package components, wherever they are nested in the component tree
# (cdxgen nests some): libraries and frameworks, plus applications/platforms
# that have a purl (Syft and cdxgen record the Node runtime that way). The
# document's own root (metadata.component) is not part of the tree.
LIBS='[(.components // []) | .. | objects | select(has("bom-ref") and ((.type? == "library" or .type? == "framework") or ((.type? == "application" or .type? == "platform") and .purl)))]'

# label|jq expression over a CycloneDX document
METRICS=(
  "Packages (total)|$LIBS | length"
  "  dev/test (not compared)|$LIBS | map(select((.scope // \"required\") != \"required\")) | length"
  "  OS source pkgs (not compared)|$LIBS | map(select((.purl // \"\") | test(\"[?&]arch=source\"))) | length"
  "with licence|$LIBS | map(select((.licenses // []) | length > 0)) | length"
  "with hashes|$LIBS | map(select((.hashes // []) | length > 0)) | length"
  "with SHA-512 (BSI)|$LIBS | map(select([(.hashes // [])[] | .alg] | index(\"SHA-512\"))) | length"
  "with CPE|$LIBS | map(select(.cpe)) | length"
  "with PURL|$LIBS | map(select(.purl)) | length"
  "File entries|[.components[]? | select(.type == \"file\")] | length"
  "Dependency edges|[(.dependencies // [])[] | (.dependsOn // [])[]] | length"
  "Root linked to deps|(.metadata.component[\"bom-ref\"]) as \$r | if \$r == null then \"no\" elif ([(.dependencies // [])[] | select(.ref == \$r) | (.dependsOn // [])[]] | length) > 0 then \"yes\" else \"no\" end"
  "Supplier set|if (.metadata.component.supplier.name // .metadata.supplier.name) then \"yes\" else \"no\" end"
  "Lifecycle (stage)|[.metadata.lifecycles[]?.phase] | join(\",\") | if . == \"\" then \"–\" else . end"
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
          | select((.purl // "") | test("/poc-[a-z]+@|/poc-[a-z]+$|sbom-poc") | not)'

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

# BuildKit's SBOM attestation is SPDX: map its packages to CycloneDX-like
# components (purl, licence, hashes) so the same metrics and diff apply.
spdx_as_cdx() {
  jq '{specVersion: ("SPDX " + (.spdxVersion | ltrimstr("SPDX-"))), metadata: {},
       components: [.packages[] | select(any(.externalRefs[]?; .referenceType == "purl")) | {
         type: "library", "bom-ref": .SPDXID,
         purl: ([.externalRefs[] | select(.referenceType == "purl") | .referenceLocator][0]),
         licenses: (if (.licenseDeclared // "NOASSERTION") | test("^(NOASSERTION|NONE)$") then [] else [{expression: .licenseDeclared}] end),
         hashes: [.checksums[]? | {alg: .algorithm, content: .checksumValue}],
         cpe: ([.externalRefs[] | select(.referenceCategory == "SECURITY") | .referenceLocator][0])}],
       # SPDX relationships -> links: "A DEPENDS_ON B" is A->B; "A DEPENDENCY_OF B" is B->A.
       # The root is what the document DESCRIBES (for BuildKit: the image).
       dependencies: ([.relationships[]?
           | if .relationshipType == "DEPENDS_ON" then {from: .spdxElementId, to: .relatedSpdxElement}
             elif .relationshipType == "DEPENDENCY_OF" then {from: .relatedSpdxElement, to: .spdxElementId}
             else empty end]
         | group_by(.from) | map({ref: .[0].from, dependsOn: [.[].to] | unique}))}
     | .metadata.component = {"bom-ref": ([input.relationships[]? | select(.relationshipType == "DESCRIBES") | .relatedSpdxElement][0])}' "$1" "$1"
}

human_size() { numfmt --to=iec --suffix=B "$(stat -c%s "$1")"; }

compare_target() {
  local app="$1" target="$2" gens=() files=()
  for g in "${GEN_ORDER[@]}"; do
    local f="$ROOT/$app/$g-$target.cdx.json"
    # the native generator's SBOM is a Build SBOM, compared with the source scans
    local label="$g"
    [[ "$g" == native && "$target" == source ]] && { f="$ROOT/$app/native-build.cdx.json"; label="native-build"; }
    [[ -s "$f" ]] && { gens+=("$label"); files+=("$f"); }
  done
  local tmp; tmp=$(mktemp -d)
  if [[ "$target" == image && -s "$ROOT/$app/buildkit-image.spdx.json" ]]; then
    spdx_as_cdx "$ROOT/$app/buildkit-image.spdx.json" > "$tmp/buildkit.cdx.json"
    gens+=("buildkit"); files+=("$tmp/buildkit.cdx.json")
  fi
  (( ${#gens[@]} > 0 )) || { rm -rf "$tmp"; return 0; }

  if [[ "$target" == source ]]; then
    echo "## Source SBOMs (pre-build) vs the Build SBOM (native-build)"
  else
    echo "## Image SBOMs: Analyzed (post-build) + BuildKit build attestation"
  fi
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
  (( ${#gens[@]} > 1 )) || { rm -rf "$tmp"; return 0; }

  # Dependency graph per generator; for source SBOMs, links compared with the
  # Build SBOM (native-build), the package manager's own tree = ground truth.
  local native_idx=-1
  for i in "${!gens[@]}"; do [[ "${gens[$i]}" == native-build ]] && native_idx=$i; done
  for i in "${!gens[@]}"; do
    jq -c -L "$SCRIPT_DIR" 'include "graph"; graph_metrics' "${files[$i]}" > "$tmp/${gens[$i]}.graph"
  done
  echo "**Dependency graph** (runtime-scope packages; the app itself excluded)"
  echo
  if (( native_idx >= 0 )); then
    echo "| Generator | Direct deps of the app | Reachable from the app | Max depth | Links | Links also in native-build |"
    echo "|---|---|---|---|---|---|"
  else
    echo "| Generator | Direct deps of the app | Reachable from the app | Max depth | Links |"
    echo "|---|---|---|---|---|"
  fi
  for i in "${!gens[@]}"; do
    local row
    row=$(jq -r --arg g "${gens[$i]}" '"| \($g) | \(.direct) | \(.reachable) | \(.depth) | \(.edges | length) |"' "$tmp/${gens[$i]}.graph")
    if (( native_idx >= 0 )); then
      row+=$(jq -r -n --slurpfile a "$tmp/${gens[$i]}.graph" --slurpfile n "$tmp/${gens[$native_idx]}.graph" '
        ($n[0].edges | length) as $total
        | ([$a[0].edges[] | select(. as $e | $n[0].edges | index($e))] | length) as $hit
        | " \($hit) of \($total)\(if $total > 0 then " (" + (($hit * 100 / $total) | floor | tostring) + "%)" else "" end) |"')
    fi
    echo "$row"
  done
  echo

  # Which generator found which package (only packages not found by all)
  for i in "${!gens[@]}"; do packages "${files[$i]}" > "$tmp/${gens[$i]}"; done
  sort -u "${gens[@]/#/$tmp/}" > "$tmp/all"
  local rows=()
  while read -r pkg; do
    local row="| \`$pkg\` |" found=0
    for g in "${gens[@]}"; do
      if grep -qxF "$pkg" "$tmp/$g"; then row+=" yes |"; found=$((found + 1)); else row+=" - |"; fi
    done
    (( found < ${#gens[@]} )) && rows+=("$row")
  done < "$tmp/all"
  local total; total=$(wc -l < "$tmp/all")
  [[ -f "$ROOT/$app/artifact.json" && "$target" == image ]] \
    && echo "Image: \`$(jq -r '.image + "@" + .index_digest' "$ROOT/$app/artifact.json")\`" && echo
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

# COMPARE_TARGETS: which tables to print (default both); NO_APP_HEADING=1 omits
# the "# <app>" heading (summary.sh places the tables under stage headings).
for app in "${APPS[@]}"; do
  [[ "${NO_APP_HEADING:-0}" == 1 ]] || { echo "# $app"; echo; }
  for t in ${COMPARE_TARGETS:-source image}; do compare_target "$app" "$t"; done
done
