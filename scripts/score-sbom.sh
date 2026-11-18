#!/usr/bin/env bash
# Scores an app's SBOMs with sbomqs and prints Markdown tables, one PER FORMAT:
# CycloneDX and SPDX encode the same data differently, so ranking them together
# mostly measures the format, not the SBOM.
#
# CycloneDX SBOMs are scored on a "packages only" copy: some generators add one
# component per file (Syft: 946 of 959 components for go), and sbomqs then
# penalises those files for having no version/PURL. Files aren't packages.
#
# Profiles: Interlynk (sbomqs default), NTIA/CISA 2026 minimum elements,
# BSI TR-03183-2 v2.1, CISA "Framing Software Component Transparency" (FSCT, 3rd ed.).
#
# Usage: scripts/score-sbom.sh <app> [out-root]
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
SBOMQS_IMAGE="${SBOMQS_IMAGE:-ghcr.io/interlynk-io/sbomqs:v2.1.3@sha256:fc5c9999caf95bbea0d0647a1f0944a61822596a0b11790494ffd78ec600b3b5}"
PROFILES="interlynk,ntia,bsi-v2.1,fsct"
WORK="$DIR/reports/quality"
OUT="$DIR/reports/quality.json"
rm -rf "$WORK" && mkdir -p "$WORK"

shopt -s nullglob
for f in "$DIR"/*.cdx.json; do
  # files and cryptographic assets (cdxgen's CBOM entries) are not packages:
  # left in, they would be scored as components missing names, versions, licences
  jq '([.components[]? | select(.type == "file" or .type == "cryptographic-asset") | .["bom-ref"]]) as $files
      | .components = [.components[]? | select(.type != "file" and .type != "cryptographic-asset")]
      | .dependencies = [(.dependencies // [])[] | select(.ref as $r | $files | index($r) | not)
                         | .dependsOn = [(.dependsOn // [])[] | select(. as $d | $files | index($d) | not)]]' \
    "$f" > "$WORK/$(basename "$f")"
done
for f in "$DIR"/*.spdx.json; do cp "$f" "$WORK/"; done
mapfile -t FILES < <(cd "$WORK" && ls -1 *.json | sort)

docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
  -v "$PWD/$WORK":/w:ro -w /w "$SBOMQS_IMAGE" score --json --profile "$PROFILES" "${FILES[@]}" \
  > "$OUT" 2> "$WORK/sbomqs.log"

table() {  # $1 = file_format value ("cyclonedx" / "spdx")
  echo "| SBOM | Interlynk | NTIA 2026 | BSI v2.1 | FSCT | Components | Missing NTIA 2026 elements |"
  echo "|---|---|---|---|---|---|---|"
  jq -r --arg fmt "$1" '
    def prof($p): ([.profiles[]? | select(.profile | test($p)) | .score][0] // null)
      | if . == null then "–" else (. * 10 | round / 10 | tostring) end;
    .files | map(select(.spec == $fmt)) | sort_by(-([.profiles[]? | select(.profile == "Interlynk") | .score][0] // 0))[] |
    "| `\(.file_name)` | **\(prof("^Interlynk"))** | \(prof("^NTIA")) | \(prof("^BSI")) | \(prof("^Framing")) | \(.num_components) | \(
       [.profiles[]? | select(.profile | test("^NTIA")) | .features[]?
        | select(.required and (.ignored | not) and .score < 5) | .key] | join(", ")) |"' "$OUT"
  echo
}

echo "## SBOM quality ($APP)"
echo
echo "Scored with [sbomqs](https://github.com/interlynk-io/sbomqs) (0–10), per format. CycloneDX scored without per-file entries. NTIA 2026 = CISA minimum elements; FSCT = CISA Framing 3rd edition."
echo
echo "**CycloneDX**"
echo
table cyclonedx
echo "**SPDX**"
echo
table spdx
