#!/usr/bin/env bash
# Checks the licences in an app's SBOMs against policy/licenses.yaml with
# anchore/grant, and prints a Markdown summary per SBOM.
#
# Only dependency SBOMs (source + native) are checked: image SBOMs also contain
# OS packages (glibc, coreutils, ...) that are GPL by nature and need a
# different policy.
#
# Usage: scripts/check-licenses.sh <app> [out-root]
# Env:   LICENSE_GATE=1  exit non-zero if the native SBOM violates the policy
#                        (default: report only)
set -euo pipefail

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
POLICY="policy/licenses.yaml"
GRANT_IMAGE="${GRANT_IMAGE:-anchore/grant:v0.8.0@sha256:b1496c1b94608176e6c515108dbc54851b8e6cda5cf7f97b4a4f2a4792e93714}"
OUT="$DIR/reports/licenses.json"

mapfile -t SBOMS < <(cd "$DIR" && ls -1 native-source.cdx.json *-source.cdx.json 2>/dev/null | sort -u)
(( ${#SBOMS[@]} > 0 )) || { echo "error: no source SBOMs in $DIR" >&2; exit 1; }
mkdir -p "$DIR/reports"

# grant exits 1 on any violation; --dry-run keeps it 0 so all results are collected
docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
  -v "$PWD":/w -w /w "$GRANT_IMAGE" -c "$POLICY" check --dry-run \
  "${SBOMS[@]/#/$DIR/}" -o json > "$OUT" 2> /dev/null

echo "## Licences ($APP)"
echo
echo "Policy: [\`$POLICY\`](../$POLICY). Checked: dependency SBOMs (source + native)."
echo
echo "| SBOM | Packages | Allowed | Denied | No licence | Non-SPDX licences | Result |"
echo "|---|---|---|---|---|---|---|"
jq -r '.run.targets[] | .source.ref as $ref | .evaluation as $e |
  "| `\($ref | split("/") | last)` | \($e.summary.packages.total) | \($e.summary.packages.allowed) | \($e.summary.packages.denied - $e.summary.packages.unlicensed) | \($e.summary.packages.unlicensed) | \($e.summary.licenses.nonSPDX) | \(if $e.status == "compliant" then "✅ pass" else "❌ fail" end) |"' "$OUT"
echo

native="$DIR/native-source.cdx.json"
if jq -e --arg f "$native" '.run.targets[] | select(.source.ref == $f)' "$OUT" > /dev/null; then
  echo "Denied packages in the **native** SBOM (licence → package):"
  echo
  jq -r --arg f "$native" '.run.targets[] | select(.source.ref == $f) | .evaluation.findings.packages[]
    | select(.decision == "deny")
    | "- `\(.name)@\(.version)`: \(if (.licenses | length) == 0 then "_no licence_" else ([.licenses[].id] | join(", ")) end)"' "$OUT" | sort
  echo
  if [[ "${LICENSE_GATE:-0}" == "1" ]] && \
     jq -e --arg f "$native" '.run.targets[] | select(.source.ref == $f) | .evaluation.status != "compliant"' "$OUT" > /dev/null; then
    echo "FAIL [$APP]: native SBOM violates the licence policy" >&2
    exit 1
  fi
fi
