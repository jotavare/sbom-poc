#!/usr/bin/env bash
# Unmanaged files: executables and libraries in the image that NO package
# claims. SBOM generators find software through package managers' metadata
# (dpkg, pip, npm, Maven, Go/Rust build info); anything copied in another way
# (curl | tar in a Dockerfile, a compiled interpreter in /usr/local, vendored
# binaries) is invisible to them. This lists those blind spots.
#
# Candidates: regular files that are executable, or look like code
# (*.so*, *.jar, *.node, *.wasm, *.a, *.pyd). Ownership: scripts/ownership.jq
# on Syft's native JSON for the same image.
#
# Usage: scripts/unmanaged-files.sh <app> [out-root]
# Output: <out-root>/<app>/reports/unmanaged.md, reports/unmanaged.txt
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
DIR="$OUT_ROOT/$APP"
IMAGE="${IMAGE:-poc-$APP:local}"
SYFT_JSON="$OUT_ROOT/.cache/$APP/syft-image.syft.json"
[[ -s "$SYFT_JSON" ]] || { echo "error: missing $SYFT_JSON (run make sbom APP=$APP first)" >&2; exit 1; }
mkdir -p "$DIR/reports"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- every candidate file in the image (listing only, nothing extracted) --------------
cid=$(docker create "$IMAGE" /none)
docker export "$cid" | tar -tvf - > "$WORK/listing.txt"
docker rm "$cid" > /dev/null
# GNU tar -tv: "-rwxr-xr-x root/root 1234 2026-01-01 00:00 path"
awk '$1 ~ /^-/ {
       path = $6; for (i = 7; i <= NF; i++) path = path " " $i
       exe = ($1 ~ /x/)
       code = (path ~ /\.so(\.[0-9]+)*$/ || path ~ /\.(jar|node|wasm|a|pyd)$/)
       if (exe || code) print "/" path "\t" $3 }' "$WORK/listing.txt" \
  | sed 's|^//|/|' \
  | grep -vE '^/(\.dockerenv|dev/|proc/|sys/|etc/(hostname|hosts|resolv\.conf)\b|var/lib/dpkg/info/)' \
  | sort -u > "$WORK/candidates.tsv"
# (excluded: files Docker adds to every container, and dpkg maintainer scripts)

# --- owned files and package directories (usrmerge-normalised) ------------------------
jq -r -L "$(dirname "$0")" 'include "ownership"; artifact_ownership[] | .files[]' "$SYFT_JSON" \
  | sort -u > "$WORK/owned.txt"
jq -r -L "$(dirname "$0")" 'include "ownership"; artifact_ownership[] | .dirs[]' "$SYFT_JSON" \
  | sort -u > "$WORK/owned-dirs.txt"

# --- candidates no package claims ------------------------------------------------------
jq -R -r -n -L "$(dirname "$0")" --rawfile owned "$WORK/owned.txt" --rawfile dirs "$WORK/owned-dirs.txt" '
  include "ownership";
  ($owned | split("\n") | map(select(. != "")) | map({key: ., value: true}) | from_entries) as $o
  | ($dirs | split("\n") | map(select(. != ""))) as $d
  | inputs | split("\t") as [$path, $size]
  | ($path | usrmerge) as $p
  | select(($o[$p] | not) and ([$d[] | select(. as $x | $p | startswith($x))] | length == 0))
  | "\($path)\t\($size)"' < "$WORK/candidates.tsv" > "$DIR/reports/unmanaged.txt"

total=$(wc -l < "$WORK/candidates.tsv")
unowned=$(wc -l < "$DIR/reports/unmanaged.txt")
{
  echo "## Unmanaged files ($APP)"
  echo
  echo "Executables and libraries in \`$IMAGE\` that no package claims: **$unowned** of $total candidates. SBOM generators only see software that a package manager recorded; these files are blind spots unless a tool identifies them another way (e.g. Syft's binary classifiers)."
  echo
  if (( unowned > 0 )); then
    echo "| Directory | Files | Size | Examples |"
    echo "|---|---|---|---|"
    awk -F'\t' '{ n = split($1, p, "/"); d = ""; for (i = 2; i < n && i <= 4; i++) d = d "/" p[i]
                  if (d == "") d = "/"; cnt[d]++; sz[d] += $2
                  if (ex[d] == "" || length(ex[d]) < 60) ex[d] = ex[d] (ex[d] == "" ? "" : ", ") "`" p[n] "`" }
         END { for (d in cnt) printf "| `%s` | %d | %.1f MB | %s |\n", d, cnt[d], sz[d] / 1048576, ex[d] }' \
      "$DIR/reports/unmanaged.txt" | sort -t'|' -k3 -rn | head -25
    echo
    echo "_Full list: \`reports/unmanaged.txt\`._"
  fi
  echo
} > "$DIR/reports/unmanaged.md"
echo "==> [$APP] unmanaged: $unowned of $total candidate files not claimed by any package"
