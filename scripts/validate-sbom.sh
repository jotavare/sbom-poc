#!/usr/bin/env bash
# Validates every SBOM of an app against its specification:
#   CycloneDX: cyclonedx-cli validate (JSON schema of the declared specVersion)
#   SPDX:      pyspdxtools from the SPDX project's spdx-tools (spec + semantics)
# Prints a Markdown table; exits non-zero if any SBOM is invalid, unless the
# file is listed in apps/<app>/sbom-invalid-ok.txt ("<file> <reason>": a known
# generator bug, reported instead of hidden).
#
# Usage: scripts/validate-sbom.sh <app> [out-root]
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
ROOT="${2:-sbom}"
DIR="$ROOT/$APP"
CDX_CLI_IMAGE="cyclonedx/cyclonedx-cli:0.33.1@sha256:252c2e26f468c25fea1e63ecde1bc3198ad6e9dbb57f5ed3236bddcb2281b3a7"
PY_IMAGE="python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
SPDX_TOOLS_VERSION="0.8.5"
ALLOW="apps/$APP/sbom-invalid-ok.txt"
LOGDIR="$DIR/reports/validation"
rm -rf "$LOGDIR" && mkdir -p "$LOGDIR" "$ROOT/.cache"
ROOT_ABS="$(cd "$ROOT" && pwd)"

# spdx-tools installed once into the cache (parallel-safe)
PYSPDX="$ROOT/.cache/spdx-tools-$SPDX_TOOLS_VERSION"
(
  flock 9
  if [[ ! -d "$PYSPDX/bin" ]]; then
    docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -v "$ROOT_ABS/.cache":/cache "$PY_IMAGE" \
      pip install -q --disable-pip-version-check --target "/cache/$(basename "$PYSPDX")" \
      "spdx-tools==$SPDX_TOOLS_VERSION" > /dev/null
  fi
) 9> "$ROOT/.cache/spdx-tools.lock"

invalid=0
echo "## Validation ($APP)"
echo
echo "| SBOM | Format | Result |"
echo "|---|---|---|"
shopt -s nullglob
for f in "$DIR"/*.cdx.json "$DIR"/views/*.cdx.json "$DIR"/*.spdx.json; do
  rel="${f#"$DIR"/}"
  log="$LOGDIR/$(tr '/' '_' <<< "$rel").log"
  if [[ "$f" == *.cdx.json ]]; then
    fmt="CycloneDX $(jq -r .specVersion "$f")"
    docker run --rm --security-opt label=disable -v "$(cd "$(dirname "$f")" && pwd)":/w:ro \
      "$CDX_CLI_IMAGE" validate --input-file "/w/$(basename "$f")" --fail-on-errors > "$log" 2>&1 && ok=1 || ok=0
  else
    fmt="$(jq -r .spdxVersion "$f")"
    docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -e PYTHONPATH="/cache/$(basename "$PYSPDX")" \
      -v "$ROOT_ABS/.cache":/cache:ro -v "$(cd "$(dirname "$f")" && pwd)":/w:ro "$PY_IMAGE" \
      python -m spdx_tools.spdx.clitools.pyspdxtools -i "/w/$(basename "$f")" > "$log" 2>&1 && ok=1 || ok=0
  fi
  if (( ok )); then
    result="✅ valid"
  else
    # most specific message: skip generic header lines, count repeats
    first=$(grep -vE "^ERROR:root:|^Validation failed|^$" "$log" | sed -E 's/\[<.*//' | sort | uniq -c | sort -rn \
            | head -1 | sed -E 's/^ *([0-9]+) (.*)/\2 (x\1)/' | cut -c1-140 | tr '|' '/')
    [[ -n "$first" ]] || first=$(head -1 "$log" | cut -c1-140 | tr '|' '/')
    if [[ -f "$ALLOW" ]] && grep -qE "^$rel[[:space:]]" "$ALLOW"; then
      result="⚠️ invalid (known: $(grep -E "^$rel[[:space:]]" "$ALLOW" | cut -d' ' -f2-)): $first"
    else
      result="❌ invalid: $first"; invalid=$((invalid + 1))
    fi
  fi
  echo "| \`$rel\` | $fmt | $result |"
done
echo
(( invalid == 0 )) || { echo "FAIL [$APP]: $invalid invalid SBOM(s), see $LOGDIR" >&2; exit 1; }
