#!/usr/bin/env bash
# Validates every SBOM of an app against its specification:
#   CycloneDX: cyclonedx-cli validate (JSON schema of the declared specVersion)
#   SPDX 2.x:  pyspdxtools from the SPDX project's spdx-tools (spec + semantics)
#   SPDX 3.x:  spdx3-validate (JSON schema + the official SHACL model shapes).
#              It exits 0 even when SHACL fails, so its output is checked instead.
#              SHACL is slow on large files (Syft's 1.5 MB go image SBOM: ~7.5 min
#              on an old laptop), so files above SPDX3_SHACL_MAX_BYTES get the
#              official JSON schema only (jsonschema-rs, scripts/spdx3_schema_check.py)
#              unless SPDX3_FULL=1. (The pure-Python check-jsonschema needed ~24 min
#              for Java's 15 MB file in CI; jsonschema-rs takes under a second.)
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
SPDX3_VALIDATE_VERSION="0.0.7"
JSONSCHEMA_RS_VERSION="0.61.2"
SPDX3_SCHEMA_URL="https://spdx.org/schema/3.0.1/spdx-json-schema.json"
SPDX3_SCHEMA_SHA256="582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1"
SPDX3_SHACL_MAX_BYTES="${SPDX3_SHACL_MAX_BYTES:-250000}"
SPDX3_FULL="${SPDX3_FULL:-0}"
ALLOW="apps/$APP/sbom-invalid-ok.txt"
LOGDIR="$DIR/reports/validation"
rm -rf "$LOGDIR" && mkdir -p "$LOGDIR" "$ROOT/.cache"
ROOT_ABS="$(cd "$ROOT" && pwd)"
SCRIPTS_ABS="$(cd "$(dirname "$0")" && pwd)"

# Python validators installed once into the cache (parallel-safe)
PYSPDX="$ROOT/.cache/spdx-tools-$SPDX_TOOLS_VERSION"
PYSPDX3="$ROOT/.cache/spdx3-validate-$SPDX3_VALIDATE_VERSION"
PYJSONSCHEMA="$ROOT/.cache/jsonschema-rs-$JSONSCHEMA_RS_VERSION"
SPDX3_SCHEMA="$ROOT/.cache/spdx-3.0.1-json-schema.json"
(
  flock 9
  if ! echo "$SPDX3_SCHEMA_SHA256  $SPDX3_SCHEMA" | sha256sum -c --status 2> /dev/null; then
    curl -fsSL --retry 3 -o "$SPDX3_SCHEMA" "$SPDX3_SCHEMA_URL"
    echo "$SPDX3_SCHEMA_SHA256  $SPDX3_SCHEMA" | sha256sum -c --status \
      || { echo "error: SPDX 3.0.1 schema checksum mismatch" >&2; exit 1; }
  fi
  for spec in "$PYSPDX spdx-tools==$SPDX_TOOLS_VERSION" "$PYSPDX3 spdx3-validate==$SPDX3_VALIDATE_VERSION" \
              "$PYJSONSCHEMA jsonschema-rs==$JSONSCHEMA_RS_VERSION"; do
    read -r dir pkg <<< "$spec"
    [[ -d "$dir" ]] && continue
    docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -v "$ROOT_ABS/.cache":/cache "$PY_IMAGE" \
      pip install -q --disable-pip-version-check --target "/cache/$(basename "$dir")" "$pkg" > /dev/null
  done
) 9> "$ROOT/.cache/py-validators.lock"

# --- run each validator ONCE over all its files (one container per validator,
#     not one per file: container start-up was most of the time) -----------------
shopt -s nullglob
FILES=()
for f in "$DIR"/*.cdx.json "$DIR"/views/*.cdx.json "$DIR"/*.spdx.json "$DIR"/*.spdx3.json; do
  FILES+=("${f#"$DIR"/}")
done
logname() { tr '/' '_' <<< "$1"; }

CDX=() SPDX2=() SPDX3_FULL_LIST=() SPDX3_SCHEMA_LIST=()
for rel in "${FILES[@]}"; do
  case "$rel" in
    *.cdx.json)   CDX+=("$rel:$(logname "$rel")") ;;
    *.spdx3.json) if [[ "$SPDX3_FULL" == 1 ]] || (( $(stat -c %s "$DIR/$rel") <= SPDX3_SHACL_MAX_BYTES )); then
                    SPDX3_FULL_LIST+=("$rel:$(logname "$rel")")
                  else
                    SPDX3_SCHEMA_LIST+=("$rel:$(logname "$rel")")
                  fi ;;
    *.spdx.json)  SPDX2+=("$rel:$(logname "$rel")") ;;
  esac
done

batch() {  # <image> <PYTHONPATH or -> <command template> <file:log pairs...>
  local image="$1" pypath="$2" cmd="$3"; shift 3
  (( $# > 0 )) || return 0
  docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" -e HOME=/tmp \
    ${pypath:+-e PYTHONPATH=/cache/$pypath} \
    -v "$ROOT_ABS/.cache":/cache:ro -v "$(cd "$DIR" && pwd)":/d:ro -v "$(cd "$LOGDIR" && pwd)":/logs \
    -v "$SCRIPTS_ABS":/scripts:ro --entrypoint sh "$image" -c '
      cmd="$1"; shift
      for spec in "$@"; do
        f="/d/${spec%%:*}"; l="/logs/${spec#*:}"
        sh -c "$cmd" _ "$f" > "$l.log" 2>&1; echo $? > "$l.rc"
      done' _ "$cmd" "$@"
}

batch "$CDX_CLI_IMAGE" "" '/cyclonedx validate --input-file "$1" --fail-on-errors' "${CDX[@]}"
batch "$PY_IMAGE" "$(basename "$PYSPDX")" 'python -m spdx_tools.spdx.clitools.pyspdxtools -i "$1"' "${SPDX2[@]}"
batch "$PY_IMAGE" "$(basename "$PYSPDX3")" 'python -m spdx3_validate --quiet --json "$1"' "${SPDX3_FULL_LIST[@]}"
batch "$PY_IMAGE" "$(basename "$PYJSONSCHEMA")" \
  'python /scripts/spdx3_schema_check.py /cache/spdx-3.0.1-json-schema.json "$1"' "${SPDX3_SCHEMA_LIST[@]}"

# --- results table ---------------------------------------------------------------
invalid=0
echo "## Validation ($APP)"
echo
echo "| SBOM | Format | Result |"
echo "|---|---|---|"
for rel in "${FILES[@]}"; do
  f="$DIR/$rel"
  log="$LOGDIR/$(logname "$rel").log"
  rc=$(cat "$LOGDIR/$(logname "$rel").rc" 2> /dev/null || echo 1)
  case "$rel" in
    *.cdx.json)   fmt="CycloneDX $(jq -r .specVersion "$f")" ;;
    *.spdx.json)  fmt="$(jq -r .spdxVersion "$f")" ;;
    *.spdx3.json) fmt="SPDX $(jq -r '.["@context"] | tostring | capture("rdf/(?<v>[0-9.]+)/").v' "$f")" ;;
  esac
  ok=$(( rc == 0 ? 1 : 0 ))
  if [[ "$rel" == *.spdx3.json ]]; then
    if printf '%s\n' "${SPDX3_SCHEMA_LIST[@]}" | grep -q "^$rel:"; then
      fmt="$fmt (schema only: $(( $(stat -c %s "$f") / 1024 )) KB, SHACL with SPDX3_FULL=1)"
    else
      # spdx3-validate exits 0 even when SHACL fails: judge by its output
      grep -qE "^ERROR:|Violation" "$log" && ok=0 || ok=1
    fi
  fi
  if (( ok )); then
    result="✅ valid"
  else
    # SHACL reports: use the "Message:" lines; otherwise the most repeated line
    # (`|| true`: head closes the pipe early, which pipefail would turn into an error)
    if grep -q "Message:" "$log"; then
      first=$(grep "Message:" "$log" | sed -E 's/^\s*Message: //' | sort | uniq -c | sort -rn \
              | head -1 | sed -E 's/^ *([0-9]+) (.*)/\2 (x\1)/' | cut -c1-140 | tr '|' '/' || true)
    else
      first=$(grep -vE "^ERROR:|^Validation failed|^Violation of|Severity:|Source Shape|Focus Node|Value Node|Result Path|^\s*$" "$log" \
              | sed -E 's/\[<.*//' | sort | uniq -c | sort -rn \
              | head -1 | sed -E 's/^ *([0-9]+) (.*)/\2 (x\1)/' | cut -c1-140 | tr '|' '/' || true)
    fi
    [[ -n "$first" ]] || first=$(head -1 "$log" | cut -c1-140 | tr '|' '/' || true)
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
