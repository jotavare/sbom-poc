#!/usr/bin/env bash
# One-off ScanCode scan of an app's dependencies as they are in the image:
# CONCLUDED licences (detected in the actual licence texts and file headers)
# and COPYRIGHT holders, compared with the DECLARED licence in package metadata
# (what every SBOM generator reports). Slow, so not part of every pipeline run.
#
# Scans the paths in apps/<app>/scancode-paths.txt (copied out of the image).
# Go and Rust images contain only compiled binaries: their dependencies'
# sources are not in the image, so there is nothing to scan there.
#
# Usage: scripts/scancode.sh <app> [out-root]
# Output: <out-root>/<app>/reports/scancode.json (raw), reports/scancode.md
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
DIR="$OUT_ROOT/$APP"
IMAGE="${IMAGE:-poc-$APP:local}"
PATHS="apps/$APP/scancode-paths.txt"
TOOL="poc-scancode:32.5.0"
mkdir -p "$DIR/reports"

if [[ ! -s "$PATHS" ]]; then
  { echo "## ScanCode ($APP)"; echo
    echo "Not applicable: the image contains compiled binaries only; dependency sources are not in it."; echo
  } > "$DIR/reports/scancode.md"
  echo "==> [$APP] scancode: skipped (no $PATHS)"; exit 0
fi

WORK="$(mktemp -d)"
# cleanup must never decide the result (the scan itself already succeeded)
trap 'rm -rf "$WORK" 2> /dev/null || true' EXIT
mkdir -p "$WORK/scan" && chmod 777 "$WORK" "$WORK/scan"

echo "==> [$APP] scancode: building tool image"
docker build -q -t "$TOOL" tools/scancode > /dev/null

echo "==> [$APP] scancode: copying paths out of $IMAGE"
cid=$(docker create "$IMAGE" /none)
while read -r p; do
  [[ -z "$p" || "$p" == \#* ]] && continue
  docker cp -q "$cid:$p" "$WORK/scan/"
done < "$PATHS"
docker rm "$cid" > /dev/null

# Run as the current user: files extracted from archives must stay deletable
run_scancode() {
  docker run --rm --security-opt label=disable --network none -e HOME=/tmp \
    --user "$(id -u):$(id -g)" -v "$WORK":/w "$@"
}
# Archives (the Java fat JAR and its nested JARs) are extracted first
if find "$WORK/scan" -name '*.jar' | grep -q .; then
  echo "==> [$APP] scancode: extracting archives"
  run_scancode --entrypoint extractcode "$TOOL" --quiet /w/scan > /dev/null
fi

echo "==> [$APP] scancode: scanning (licences, copyrights, packages)"
start=$SECONDS
run_scancode "$TOOL" --license --copyright --package --strip-root --quiet \
  --processes "$(nproc)" --timeout 120 --json /w/scancode.json /w/scan
cp "$WORK/scancode.json" "$DIR/reports/scancode.json"
echo "==> [$APP] scancode: done ($((SECONDS - start))s)"

# --- per package: declared vs detected licences, copyright holders --------------------
{
  echo "## ScanCode: declared vs detected licences ($APP)"
  echo
  echo "Declared = package metadata (what SBOM generators report). Detected = ScanCode's findings in the package's own files (licence texts, headers). "(+)" = detected licences that the declaration doesn't mention (pointers like "see LICENSE", reported as \`LicenseRef-scancode-unknown-license-reference\`, are not flagged)."
  echo
  echo "| Package | Declared | Detected in files | Copyright holders |"
  echo "|---|---|---|---|"
  jq -r '
    (.files // []) as $files
    | [ .packages[]? | . as $p
        | ([$files[] | select((.for_packages // []) | index($p.package_uid))]) as $pf
        | ([$pf[] | .detected_license_expression_spdx // empty] | unique) as $det
        | ([$pf[] | .holders[]?.holder] | unique) as $holders
        | ($p.declared_license_expression_spdx // "") as $decl
        | ([$det[] | split(" ")[] | select(test("^[A-Za-z0-9.+-]+$") and (. != "AND" and . != "OR" and . != "WITH"))] | unique) as $detIds
        # "unknown-license-reference" only means a file points to a licence
        # ("see LICENSE"), not a different licence: not flagged
        | ([$detIds[] | select(startswith("LicenseRef-scancode-unknown") | not)
            | select(. as $i | ($decl | split(" ") | index($i)) | not)]) as $extra
        | {name: ("\($p.name)@\($p.version // "?")"), decl: $decl, det: ($detIds | join(", ")),
           extra: $extra, holders: ($holders | .[0:3] | join("; ")), nh: ($holders | length)} ]
    | sort_by(.name)[]
    | "| `\(.name)` | \(if .decl == "" then "_none_" else "`" + .decl + "`" end) | \(.det)\(if (.extra | length) > 0 then " (+)" else "" end) | \(.holders)\(if .nh > 3 then " (+\(.nh - 3))" else "" end) |"' \
    "$DIR/reports/scancode.json"
  echo
  echo "_Raw results: \`reports/scancode.json\`. Packages ScanCode assembled from the scanned files only._"
  echo
} > "$DIR/reports/scancode.md"
