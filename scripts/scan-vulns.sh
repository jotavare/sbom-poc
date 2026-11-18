#!/usr/bin/env bash
# Iteration 2: vulnerability scan of the SBOMs (no image or source access needed:
# the SBOM is the input, which is the point of having one).
#
#   Scanners  Grype, Trivy (`trivy sbom`), OSV-Scanner: three databases
#             (Anchore's, Aqua's, osv.dev), so their disagreements show.
#   SBOMs     stage 3 image SBOMs from Syft, Trivy and cdxgen, and the stage 2
#             native build SBOM: does the generator change what is found?
#   Output    sbom/<app>/vulns/<scanner>-<sbom>.json (raw), findings.json
#             (normalised, see vulns.jq), grype-syft-image.sarif (Grype's own),
#             vulns.sarif (the merged findings, one result each: vulns-sarif.jq), and
#             sbom/<app>/reports/vulns.md:
#               - findings per scanner and SBOM
#               - scanner agreement on the image
#               - planted CVEs (apps/<app>/vuln-expect.txt) each scanner found
#               - what to fix first: KEV, runs (runtime SBOM), severity, EPSS
#               - the gate
#
# What counts for the gate is the UNION of every scanner on every image SBOM
# (stage 3). No single pair sees everything: Debian advisories are per source
# package, and each generator records it differently (Trivy: its own property,
# Syft: a purl "upstream=" qualifier, cdxgen: not at all); OSV-Scanner only
# reads "distro=debian-13" (cdxgen), not "debian-13.7" (Syft, Trivy).
#
# Gate (fails the build): a critical or high vulnerability WITH A FIX in that
# union, unless its package or ID is accepted in apps/<app>/vuln-accept.txt:
#     <package without version | package prefix* | vulnerability ID> <expires YYYY-MM-DD> <reason>
# Expired entries no longer apply. Vulnerabilities without a fix are reported,
# not gated: nothing can be done about them but accept or remove the package.
# Also fails if no scanner finds a planted CVE (the pipeline would be blind).
# This script only reports and writes the verdict to sbom/<app>/vulns/gate.status;
# `make vuln-gate` (scripts/vuln-gate.sh) fails on it, after the summary is written.
#
# Usage: scripts/scan-vulns.sh <app> [out-root]
#   VULN_SKIP_SCAN=1  reuse the raw scanner output (rebuild the report and verdict only)
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: scan-vulns.sh <app> [out-root]}"
ROOT="${2:-sbom}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="$ROOT/$APP"
OUT="$DIR/vulns"
R="$DIR/reports"
APPDIR="apps/$APP"
DB="${VULN_DB_DIR:-$ROOT/.cache/vulndb}"          # shared by all apps; one download per day
GATE_SBOM="syft-image"                  # must exist; SARIF is written for it
SBOMS="${VULN_SBOMS:-syft-image trivy-image cdxgen-image native-build}"
SCANNERS="grype trivy osv"
TIMEOUT="${VULN_TIMEOUT:-600}"

GRYPE_IMAGE="${GRYPE_IMAGE:-anchore/grype:v0.121.3@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb}"
OSV_IMAGE="${OSV_IMAGE:-ghcr.io/google/osv-scanner:v2.7.1@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde}"

[[ -s "$DIR/$GATE_SBOM.cdx.json" ]] || { echo "error: $DIR/$GATE_SBOM.cdx.json missing (make sbom APP=$APP)" >&2; exit 1; }
mkdir -p "$OUT/logs" "$R" "$DB/grype" "$DB/trivy"
DIR_ABS="$(cd "$DIR" && pwd)"; OUT_ABS="$(cd "$OUT" && pwd)"; DB_ABS="$(cd "$DB" && pwd)"

run() {
  timeout "$TIMEOUT" docker run --rm --security-opt label=disable \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:mode=1777,size=4g -e HOME=/tmp \
    -v "$DIR_ABS":/sbom:ro -v "$OUT_ABS":/out -v "$DB_ABS":/db "$@"
}
GRYPE_ENV=(-e GRYPE_DB_CACHE_DIR=/db/grype -e GRYPE_CHECK_FOR_APP_UPDATE=false)

# --- 1. databases: updated once, under a lock (parallel `make -j` runs share them) ---
t0=$SECONDS
# A DB is refreshed only when it is older than VULN_DB_MAX_AGE_HOURS (default 12):
# both scanners publish several builds a day, and fetching the newest on every
# run made the daily CI cache useless (~40 s per job). The report shows the DB date.
MAX_AGE=$(( ${VULN_DB_MAX_AGE_HOURS:-12} * 3600 ))
older_than_max() {  # <ISO timestamp or empty>: true if missing or too old
  [[ -n "$1" ]] || return 0
  local ts; ts="$(date -u -d "$1" +%s 2> /dev/null)" || return 0
  (( $(date -u +%s) - ts > MAX_AGE ))
}
[[ "${VULN_SKIP_SCAN:-}" == 1 ]] || (
  flock 9
  built="$(run "${GRYPE_ENV[@]}" "$GRYPE_IMAGE" db status -o json 2> /dev/null | jq -r '.built // empty' || true)"
  if older_than_max "$built"; then
    run "${GRYPE_ENV[@]}" "$GRYPE_IMAGE" db update > "$OUT/logs/grype-db.log" 2>&1
  else echo "grype DB built $built: fresh enough" > "$OUT/logs/grype-db.log"; fi
  updated="$(jq -r '.UpdatedAt // empty' "$DB/trivy/db/metadata.json" 2> /dev/null || true)"
  if older_than_max "$updated"; then
    run "$TRIVY_IMAGE" --cache-dir /db/trivy image --download-db-only --no-progress > "$OUT/logs/trivy-db.log" 2>&1
  else echo "trivy DB updated $updated: fresh enough" > "$OUT/logs/trivy-db.log"; fi
  # the DB versions in use: CI keys its DB cache on this file, so a refreshed DB
  # is saved once and restored by later runs
  printf 'grype %s\ntrivy %s\n' \
    "$(run "${GRYPE_ENV[@]}" "$GRYPE_IMAGE" db status -o json 2> /dev/null | jq -r '.built // empty' || true)" \
    "$(jq -r '.UpdatedAt // empty' "$DB/trivy/db/metadata.json" 2> /dev/null || true)" > "$DB/versions.txt"
) 9> "$DB/lock"
echo "vulnerability databases ready ($((SECONDS - t0)) s)"
[[ -s "$DB/versions.txt" ]] && cp "$DB/versions.txt" "$OUT/db-versions.txt"   # for the report header

# --- 2. scans: the three scanners run in parallel, each over every SBOM ---
scan() {
  local scanner="$1" s rc
  for s in $SBOMS; do
    [[ -s "$DIR/$s.cdx.json" ]] || continue
    local log="$OUT/logs/$scanner-$s.log" t=$SECONDS
    rc=0
    case "$scanner" in
      grype)
        local sarif=(); [[ "$s" == "$GATE_SBOM" ]] && sarif=(-o "sarif=/out/grype-$s.sarif")
        run "${GRYPE_ENV[@]}" -e GRYPE_DB_AUTO_UPDATE=false "$GRYPE_IMAGE" \
          "sbom:/sbom/$s.cdx.json" -o "json=/out/grype-$s.json" "${sarif[@]}" > "$log" 2>&1 || rc=$? ;;
      trivy)
        run "$TRIVY_IMAGE" --cache-dir /db/trivy sbom --skip-db-update --skip-java-db-update \
          --scanners vuln --format json -o "/out/trivy-$s.json" "/sbom/$s.cdx.json" > "$log" 2>&1 || rc=$? ;;
      osv)
        # exit 1 = vulnerabilities found; uses the osv.dev API (package names + versions).
        # Reads a copy without file and cryptographic-asset components: they are
        # not packages, and OSV-Scanner logs a warning for every one of them.
        jq '.components = [.components[]? | select(.type != "file" and .type != "cryptographic-asset")]' \
          "$DIR/$s.cdx.json" > "$OUT/osv-input-$s.cdx.json"
        run -v "$OUT_ABS/osv-input-$s.cdx.json:/in/$s.cdx.json:ro" "$OSV_IMAGE" scan source -L "/in/$s.cdx.json" --format json \
          --output-file "/out/osv-$s.json" > "$log" 2>&1 || rc=$?
        (( rc == 1 )) && rc=0 ;;
    esac
    if (( rc != 0 )); then
      echo "error: $scanner on $s.cdx.json failed (exit $rc), see $log" >&2
      rm -f "$OUT/$scanner-$s.json"
    else
      echo "$scanner $s: $((SECONDS - t)) s"
    fi
  done
}
if [[ "${VULN_SKIP_SCAN:-}" != 1 ]]; then
  pids=()
  for sc in $SCANNERS; do scan "$sc" & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p" || true; done
  rm -f "$OUT"/osv-input-*.cdx.json
fi

# --- 3. normalise: one finding per (scanner, SBOM, package, vulnerability) ---
# Debian source package -> the binary packages built from it, from the image
# SBOMs' own source-name records (Syft: purl "upstream=", Trivy: SrcName
# property; a binary without one is its own source). cdxgen lists source
# packages as separate components; their findings are moved onto the binaries.
img_sboms=(); for s in syft-image trivy-image cdxgen-image; do [[ -s "$DIR/$s.cdx.json" ]] && img_sboms+=("$DIR/$s.cdx.json"); done
SRCMAP_JSON="$(jq -s -c -L "$HERE" 'include "graph";
  [ .[] | .components[]? | select((.purl // "") | startswith("pkg:deb/"))
    | select(.purl | test("[?&]arch=source") | not)
    | { bin: (.purl | norm_purl),
        ns: (.purl | capture("^pkg:deb/(?<n>[^/]+)/").n),
        src: ( ((.purl | capture("[?&]upstream=(?<u>[^&#]+)").u) // null
                 | if . then gsub("%40"; "@") | split("@")[0] else null end)
               // ([.properties[]? | select(.name == "aquasecurity:trivy:SrcName") | .value][0])
               // .name ) } ]
  | group_by("\(.ns)/\(.src)") | map({key: "deb/\(.[0].ns)/\(.[0].src | ascii_downcase)", value: (map(.bin) | unique)}) | from_entries' "${img_sboms[@]}")"

for f in "$OUT"/{grype,trivy,osv}-*.json; do
  [[ -s "$f" ]] || continue
  b="$(basename "$f" .json)"
  jq -c -L "$HERE" --arg scanner "${b%%-*}" --arg sbom "${b#*-}" 'include "vulns"; findings' "$f"
done | jq -s -L "$HERE" --argjson srcmap "$SRCMAP_JSON" 'include "vulns";
  map(if .src then ((.pkg | sub("@[^@]*$"; "")) as $k | ($srcmap[$k] // null) as $bins
        | if $bins then ($bins[] as $b | . + {pkg: $b, via_source: $k}) else . end)
      else . end)
  | group_by([.scanner, .sbom, .pkg, .id]) | map(
    .[0] + {ids: (map(.ids[]) | unique), sev: (max_by(.sev | sev_rank) | .sev),
            fixed: any(.fixed), fix: (map(.fix[]) | unique),
            epss: ([.[].epss | numbers] | max), kev: any(.kev == true)})' > "$OUT/findings.json"

# packages that ran (runtime SBOM, stage 4)
RUNTIME_JSON="null"
[[ -s "$DIR/runtime.cdx.json" ]] && RUNTIME_JSON="$(jq -c -L "$HERE" 'include "graph"; [.components[]?.purl // empty | norm_purl] | unique' "$DIR/runtime.cdx.json")"

# accepted risks: "<package|ID> <expires> <reason>"
TODAY="$(date -u +%F)"
ACCEPT_JSON="$( { grep -vE '^\s*(#|$)' "$APPDIR/vuln-accept.txt" 2> /dev/null || true; } \
  | jq -R -s -c --arg today "$TODAY" 'split("\n") | map(select(length > 0) | capture("^(?<key>\\S+)\\s+(?<expires>\\S+)\\s+(?<reason>.*)$"))
      | map(. + {valid: (.expires >= $today)})')"
EXPECT_JSON="$( { grep -vE '^\s*(#|$)' "$APPDIR/vuln-expect.txt" 2> /dev/null || true; } \
  | jq -R -s -c 'split("\n") | map(select(length > 0) | capture("^(?<id>\\S+)\\s*(?<note>.*)$"))')"

# union of all scanners on all image SBOMs, per (package, vulnerability)
jq -L "$HERE" --argjson runtime "$RUNTIME_JSON" --argjson accept "$ACCEPT_JSON" 'include "vulns";
  [.[] | select(.sbom | endswith("-image"))] | group_by([.pkg, .id]) | map(
    # Severity: Grype and Trivy use the rating of the distribution or advisory
    # itself (Debian "negligible", GHSA "moderate"); OSV-Scanner only gives a
    # CVSS score (from NVD for Debian CVEs). The vendor rating wins; the highest of
    # those if they differ; the OSV CVSS rating only when no other is known.
    # Fix versions likewise: Grype/Trivy first; from OSV, its highest fixed version.
    ([.[] | select(.scanner != "osv" and .sev != "unknown")]) as $vendor
    | ([.[] | select(.scanner != "osv") | .fix[]] | unique) as $vfix
    | .[0] + {scanners: (map(.scanner) | unique), pairs: (map("\(.scanner)@\(.sbom)") | unique), ids: (map(.ids[]) | unique),
            sevs: (group_by(.scanner) | map({key: .[0].scanner, value: (max_by(.sev | sev_rank) | .sev)}) | from_entries),
            sev: (if ($vendor | length) > 0 then ($vendor | max_by(.sev | sev_rank) | .sev) else (max_by(.sev | sev_rank) | .sev) end),
            fixed: any(.fixed),
            fix: (if ($vfix | length) > 0 then ($vfix | sort_by(vkey))
                  else ([.[].fix[]] | unique | sort_by(vkey) | if length > 0 then [last] else [] end) end),
            epss: ([.[].epss | numbers] | max), kev: any(.kev == true)})
  | map(. as $f | (.pkg | split("@")[0]) as $name
      | . + {runs: (if $runtime == null then null else ($runtime | index($f.pkg)) != null end),
             accepted: ([$accept[] | . as $a | select($a.valid and ($a.key == $name or ($f.ids | index($a.key) != null)
                                 or (($a.key | endswith("*")) and ($name | startswith($a.key | rtrimstr("*"))))))][0].key // null)})' \
  "$OUT/findings.json" > "$OUT/gate.json"

# --- SARIF of the merged findings, one result each (vulns-sarif.jq) ----------------
case "$APP" in
  python) manifest=(pypi "$APPDIR/requirements.txt") ;;
  node)   manifest=(npm "$APPDIR/package-lock.json") ;;
  go)     manifest=(golang "$APPDIR/go.mod") ;;
  java)   manifest=(maven "$APPDIR/pom.xml") ;;
  rust)   manifest=(cargo "$APPDIR/Cargo.lock") ;;
  *)      manifest=(none "$APPDIR/Dockerfile") ;;
esac
FILES_JSON="$(jq -n --arg t "${manifest[0]}" --arg uri "${manifest[1]}" --rawfile txt "${manifest[1]}" \
  --arg d "$APPDIR/Dockerfile" --rawfile dtxt "$APPDIR/Dockerfile" \
  '{($t): {uri: $uri, lines: ($txt | split("\n"))}, deb: {uri: $d, lines: ($dtxt | split("\n"))}}')"
jq -L "$HERE" --arg app "$APP" --argjson accept "$ACCEPT_JSON" --argjson files "$FILES_JSON" \
  -f "$HERE/vulns-sarif.jq" "$OUT/gate.json" > "$OUT/vulns.sarif"

# --- 4. report ---------------------------------------------------------------------
label() { case "$1" in native-build) echo "\`$1.cdx.json\` (2 build)" ;; *) echo "\`$1.cdx.json\` (3 image)" ;; esac; }
{
echo "## Vulnerabilities ($APP)"
echo
echo "Three scanners, three databases: [Grype](https://github.com/anchore/grype) (Anchore), [Trivy](https://github.com/aquasecurity/trivy) (\`trivy sbom\`, Aqua) and [OSV-Scanner](https://github.com/google/osv-scanner) (osv.dev). They read the **SBOMs**, never the image. Findings are counted per package and vulnerability, after mapping each scanner's IDs (GHSA, PYSEC, RUSTSEC…) to the CVE when there is one. Grype DB built: $(jq -r '.descriptor.db.status.built // .descriptor.db.built // "?"' "$OUT/grype-$GATE_SBOM.json" 2> /dev/null || echo '?')."
echo
echo "### Findings per scanner and SBOM"
echo
echo "Cells: findings (critical / high). The SBOM decides what the scanner can match."
echo
echo "| SBOM | Grype | Trivy | OSV-Scanner |"
echo "|---|---|---|---|"
for s in $SBOMS; do
  [[ -s "$DIR/$s.cdx.json" ]] || continue
  row="| $(label "$s") |"
  for sc in $SCANNERS; do
    if [[ -s "$OUT/$sc-$s.json" ]]; then
      row+=" $(jq -r --arg s "$s" --arg sc "$sc" '[.[] | select(.sbom == $s and .scanner == $sc)]
        | "\(length) (\(map(select(.sev == "critical")) | length) / \(map(select(.sev == "high")) | length))"' "$OUT/findings.json") |"
    else row+=" failed |"; fi
  done
  echo "$row"
done
echo
echo "Why the same image gives different numbers: Debian publishes its advisories per **source** package (\`krb5\`), while an SBOM lists binary packages (\`libgssapi-krb5-2\`). Each generator records the source differently: Trivy in a property (\`aquasecurity:trivy:SrcName\`), Syft as a purl qualifier (\`upstream=krb5\`), cdxgen as separate \`arch=source\` components. A scanner reading another generator's SBOM misses most OS vulnerabilities. OSV-Scanner reads Debian packages only with \`distro=debian-13\` (cdxgen), not \`debian-13.7\` (Syft, Trivy). Findings on cdxgen's source components are counted on the binary packages built from them, so a flaw is not counted twice. Language packages match everywhere: their purl is all a scanner needs."
if jq -e '[.[] | select(.scanner == "osv" and (.pkg | startswith("golang/stdlib@")))] | length > 20' "$OUT/findings.json" > /dev/null; then
  echo
  echo "**OSV-Scanner and the Go standard library:** OSV-Scanner reads the CycloneDX component's version, not the purl's. Syft writes \`go1.27.4\` there (purl: \`1.27.4\`), which OSV-Scanner can't compare, so it reports every Go stdlib advisory ever published: false positives. On SBOMs that write the version without \`go\`, it finds none."
fi
echo

echo "### OS-package coverage"
echo
echo "How many of each image SBOM's Debian packages got any finding, per scanner. **0 means the scanner couldn't match that SBOM's OS packages**, not that they are clean (see above); the gate uses the union, so one blind pair doesn't hide anything, but a pair that suddenly drops to 0 means a tool changed."
echo
echo "| SBOM | Debian packages | Grype | Trivy | OSV-Scanner |"
echo "|---|---|---|---|---|"
for s in $SBOMS; do
  [[ "$s" == *-image && -s "$DIR/$s.cdx.json" ]] || continue
  ndeb=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:deb/")) | select(.purl | test("[?&]arch=source") | not)] | length' "$DIR/$s.cdx.json")
  row="| \`$s.cdx.json\` | $ndeb |"
  for sc in $SCANNERS; do
    if [[ ! -s "$OUT/$sc-$s.json" ]]; then row+=" failed |"; continue; fi
    n=$(jq --arg s "$s" --arg sc "$sc" '[.[] | select(.sbom == $s and .scanner == $sc and (.pkg | startswith("deb/"))) | .pkg] | unique | length' "$OUT/findings.json")
    if [[ "$sc" == trivy ]] && grep -q 'Unsupported os' "$OUT/logs/trivy-$s.log" 2> /dev/null; then
      row+=" not scanned (no OS in the SBOM) |"
    else
      row+=" $n |"
    fi
  done
  echo "$row"
done
echo

echo "### Do the scanners agree? (all image SBOMs)"
echo
echo "A finding counts for a scanner if it reported it on any of the image SBOMs."
echo
echo "| Found by | Findings | Critical + high |"
echo "|---|---|---|"
jq -r 'group_by(.scanners | join(" + ")) | sort_by([-(.[0].scanners | length), (.[0].scanners | join(" + "))])[]
  | "| \(.[0].scanners | join(" + ")) | \(length) | \(map(select(.sev == "critical" or .sev == "high")) | length) |"' "$OUT/gate.json" \
  | sed 's/grype/Grype/g; s/trivy/Trivy/g; s/osv/OSV/g'
echo
fp=$(jq '[.[] | select(.scanners == ["osv"] and (.pkg | startswith("golang/stdlib@")))] | length' "$OUT/gate.json")
if (( fp > 0 )); then
  echo "Of the OSV-only findings, $fp are on the Go standard library: the false positives explained above."
  echo
fi
single="$(jq -r '[.[] | select((.scanners | length) == 1 and (.sev == "critical" or .sev == "high"))]
  | sort_by(.scanners[0], .pkg)[] | "| \(.scanners[0]) | `\(.pkg)` | \(.id) | \(.sev) |"' "$OUT/gate.json")"
if [[ -n "$single" ]]; then
  echo "<details><summary>Critical/high found by only one scanner ($(wc -l <<< "$single"))</summary>"
  echo
  echo "| Scanner | Package | Vulnerability | Severity |"
  echo "|---|---|---|---|"
  echo "$single"
  echo
  echo "</details>"
  echo
fi

echo "### Planted vulnerabilities (\`vuln-expect.txt\`)"
echo
echo "Which scanner (**G**rype, **T**rivy, **O**SV) found each planted CVE, per SBOM. A CVE no scanner finds on any image SBOM fails the build."
echo
hdr="| CVE | Note |"; sep="|---|---|"
for s in $SBOMS; do [[ -s "$DIR/$s.cdx.json" ]] && { hdr+=" \`$s\` |"; sep+="---|"; }; done
echo "$hdr"; echo "$sep"
MISSED=0
while IFS=$'\t' read -r id note; do
  row="| $id | $note |"
  for s in $SBOMS; do
    [[ -s "$DIR/$s.cdx.json" ]] || continue
    got="$(jq -r --arg id "$id" --arg s "$s" '[.[] | select(.sbom == $s and (.ids | index($id)))] | map(.scanner[0:1] | ascii_upcase) | unique | join(" ")' "$OUT/findings.json")"
    [[ -z "$got" ]] && got="**missed**"
    row+=" $got |"
  done
  jq -e --arg id "$id" 'any(.[]; .ids | index($id))' "$OUT/gate.json" > /dev/null || MISSED=$((MISSED + 1))
  echo "$row"
done < <(jq -r '.[] | [.id, .note] | @tsv' <<< "$EXPECT_JSON")
echo

echo "### What to fix first (image)"
echo
jq -r 'map(select(.sev == "critical" or .sev == "high")) as $ch
  | "**\($ch | length)** critical/high findings; **\($ch | map(select(.fixed)) | length)** have a fix; **\($ch | map(select(.runs == true)) | length)** are in packages that ran (runtime SBOM); **\($ch | map(select(.kev)) | length)** are in CISA KEV (actively exploited)."' "$OUT/gate.json"
echo
echo "Order: known exploited (KEV), then the package ran, then severity, then EPSS (probability of exploitation in the next 30 days). Severity is the rating Grype and Trivy report (the distribution's or the advisory's own, e.g. Debian \"negligible\"); OSV-Scanner's CVSS-based rating is used only when they have none. **Ran** comes from the runtime SBOM: the package's files were used while the probes ran. For Go and Rust that means the module is compiled into the binary, not that the vulnerable function was called (that needs a reachability tool, e.g. govulncheck)."
echo
prio="$(jq -r -L "$HERE" 'include "vulns";
  map(select(.sev == "critical" or .sev == "high"))
  | sort_by([(if .kev then 0 else 1 end), (if .runs == true then 0 else 1 end), -(.sev | sev_rank), -(.epss // 0)])[]
  | "| `\(.pkg)` | \(.id) | \(.sev) | \(if .epss then "\(.epss * 1000 | round / 10)%" else "–" end) | \(if .kev then "**yes**" else "" end) | \(if .runs == true then "yes" elif .runs == false then "no" else "?" end) | \(if .fixed then (.fix | join(", ") | if . == "" then "yes" else . end) else "no fix" end) | \(.scanners | join(", ")) |"' "$OUT/gate.json")"
hdr="| Package | Vulnerability | Severity | EPSS | KEV | Ran | Fixed in | Scanners |"
if [[ -n "$prio" ]]; then
  echo "$hdr"; echo "|---|---|---|---|---|---|---|---|"
  head -15 <<< "$prio"
  echo
  if (( $(wc -l <<< "$prio") > 15 )); then
    echo "<details><summary>All $(wc -l <<< "$prio") critical/high findings</summary>"; echo
    echo "$hdr"; echo "|---|---|---|---|---|---|---|---|"; echo "$prio"; echo; echo "</details>"; echo
  fi
fi

echo "### Gate"
echo
echo "Policy: no critical/high vulnerability **with a fix** in the image (any scanner, any image SBOM), unless accepted in \`apps/$APP/vuln-accept.txt\` (package or ID, with an expiry date). Vulnerabilities without a fix are reported above, not gated."
echo
blocked="$(jq -r '[.[] | select((.sev == "critical" or .sev == "high") and .fixed and .accepted == null)]
  | sort_by(.pkg, .id)[] | "| `\(.pkg)` | \(.id) | \(.sev) | \(.fix | join(", ")) |"' "$OUT/gate.json")"
accepted="$(jq -r '[.[] | select((.sev == "critical" or .sev == "high") and .fixed and .accepted != null)] | length' "$OUT/gate.json")"
BLOCKED=0
if [[ -n "$blocked" ]]; then
  BLOCKED="$(wc -l <<< "$blocked")"
  echo "**Fail: $BLOCKED blocking** ($accepted accepted):"
  echo
  echo "| Package | Vulnerability | Severity | Fixed in |"
  echo "|---|---|---|---|"
  echo "$blocked"
else
  echo "**Pass**: nothing blocking ($accepted critical/high with a fix accepted)."
fi
echo
if [[ "$ACCEPT_JSON" != "[]" ]]; then
  echo "| Accepted | Expires | Critical/high with a fix it covers | Reason |"
  echo "|---|---|---|---|"
  jq -r --slurpfile g "$OUT/gate.json" '.[] | . as $a
    | "| `\(.key)` | \(.expires)\(if .valid then "" else " (expired)" end) | \([$g[0][] | select(.accepted == $a.key and (.sev == "critical" or .sev == "high") and .fixed)] | length) | \(.reason) |"' <<< "$ACCEPT_JSON"
  echo
fi
if (( MISSED > 0 )); then echo "**Fail: $MISSED planted CVE(s) not found by any scanner** on any image SBOM."; echo; fi
} > "$R/vulns.md"

if (( BLOCKED > 0 || MISSED > 0 )); then
  echo "fail blocking=$BLOCKED planted_missed=$MISSED" > "$OUT/gate.status"
else
  echo "pass" > "$OUT/gate.status"
fi
echo "report: $R/vulns.md (gate: $(cat "$OUT/gate.status"))"
