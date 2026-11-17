#!/usr/bin/env bash
# Scores every SBOM of an app with sbomqs (0-10, plus NTIA/BSI profiles) and
# prints a Markdown table.
#
# Usage: scripts/score-sbom.sh <app> [out-root]
set -euo pipefail

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
SBOMQS_IMAGE="${SBOMQS_IMAGE:-ghcr.io/interlynk-io/sbomqs:v2.1.3@sha256:fc5c9999caf95bbea0d0647a1f0944a61822596a0b11790494ffd78ec600b3b5}"
OUT="$DIR/reports/quality.json"

mapfile -t SBOMS < <(cd "$DIR" && ls -1 *.json 2>/dev/null | sort)
(( ${#SBOMS[@]} > 0 )) || { echo "error: no SBOMs in $DIR" >&2; exit 1; }
mkdir -p "$DIR/reports"

docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
  -v "$PWD":/w -w /w "$SBOMQS_IMAGE" score --json "${SBOMS[@]/#/$DIR/}" > "$OUT" 2> /dev/null

echo "## SBOM quality ($APP)"
echo
echo "Scored with [sbomqs](https://github.com/interlynk-io/sbomqs) (0–10). NTIA = NTIA Minimum Elements, BSI = BSI TR-03183-2."
echo
echo "| SBOM | Score | Grade | NTIA | BSI | Components | Top gaps |"
echo "|---|---|---|---|---|---|---|"
jq -r '
  def prof($p): ([.profiles[]? | select(.profile | test($p)) | .score][0] // null)
    | if . == null then "–" else (. * 10 | round / 10 | tostring) end;
  .files | sort_by(-.sbom_quality_score)[] |
  "| `\(.file_name | split("/") | last)` | **\(.sbom_quality_score * 10 | round / 10)** | \(.grade) | \(prof("^NTIA")) | \(prof("^BSI")) | \(.num_components) | \(
     [.comprehenssive[]?.features[]? | select(.ignored | not) | select(.score < 5) | .key] | .[0:3] | join(", ")) |"' "$OUT"
echo
