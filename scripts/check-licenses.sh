#!/usr/bin/env bash
# Checks the licences of an app's DEPENDENCIES against policy/licenses.yaml with
# anchore/grant, and prints a Markdown summary.
#
# Checked: source SBOMs, the native SBOM, and the image *app* views (language
# packages inside the image). Not checked: OS packages (glibc, coreutils, ...),
# which are GPL by nature and need a separate policy.
#
# Before grant runs, each component's licences are normalised (normalise_licences):
#   - several licence entries on one component are joined with OR. CycloneDX
#     doesn't say whether a list of licences is a choice (dual licensing, e.g.
#     jakarta.annotation-api: EPL-2.0 or GPL-2.0 WITH Classpath-exception-2.0)
#     or a conjunction (files under different licences, e.g. yaml.v2: Apache-2.0
#     and MIT). OR follows the dual-licence case; with AND, every dual-licensed
#     package would wrongly fail. A generator that knows uses an expression,
#     which is kept as is; grant evaluates expressions (OR: any allowed one
#     passes, AND: all must be allowed)
#   - non-standard exception names are mapped to SPDX ("WITH classpath-exception",
#     the deprecated "GPL-2.0-with-classpath-exception")
#   - components without a version are dropped (not packages)
#   - unambiguous Python classifiers are mapped to SPDX IDs ("MIT License");
#     ambiguous ones ("BSD License": which BSD?) stay unknown
#   - if a component has any SPDX ID, leftover classifier text is dropped
# Statuses: allowed, violation (an SPDX licence the policy doesn't allow, or an
# unparsed GPL-family name), unknown (no licence, or not machine-readable such as
# "BSD-like"), ignored (the app itself, the Go standard library).
#
# Usage: scripts/check-licenses.sh <app> [out-root]
# Env:   LICENSE_GATE=1  exit non-zero if the native SBOM has a violation
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
POLICY="policy/licenses.yaml"
GRANT_IMAGE="${GRANT_IMAGE:-anchore/grant:v0.8.0@sha256:b1496c1b94608176e6c515108dbc54851b8e6cda5cf7f97b4a4f2a4792e93714}"
WORK="$DIR/reports/licenses"
OUT="$DIR/reports/licenses.json"
rm -rf "$WORK" && mkdir -p "$WORK"

mapfile -t SBOMS < <(cd "$DIR" && ls -1 native-build.cdx.json *-source.cdx.json views/*-image-app.cdx.json 2> /dev/null | sort -u)
(( ${#SBOMS[@]} > 0 )) || { echo "error: no dependency SBOMs in $DIR" >&2; exit 1; }

# --- normalise ------------------------------------------------------------------
NORMALISE='
  def classifier_map: {
    "License :: OSI Approved :: MIT License": "MIT",
    "MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense"
  };
  def spdx_like: test("^[A-Za-z0-9.+-]+( WITH [A-Za-z0-9.+-]+)?$");
  def spdx_fix: gsub("WITH classpath-exception(-2\\.0)?"; "WITH Classpath-exception-2.0")
    | gsub("GPL-2\\.0-with-classpath-exception"; "GPL-2.0-only WITH Classpath-exception-2.0");
  def normalise_licences:
    [ (.licenses // [])[] |
      if .expression then {k: "spdx", v: .expression}
      elif .license.id then {k: "spdx", v: .license.id}
      elif .license.name then
        (classifier_map[.license.name] // null) as $m
        | if $m then {k: "spdx", v: $m}
          elif (.license.name | spdx_like) then {k: "spdx", v: .license.name}
          else {k: "text", v: .license.name} end
      else empty end ] as $l
    | ([$l[] | select(.k == "spdx") | .v | spdx_fix] | unique) as $spdx
    | if ($spdx | length) > 0 then
        .licenses = [{expression: ($spdx | map(if test(" ") then "(" + . + ")" else . end) | join(" OR "))}]
      else
        .licenses = [$l[] | {license: {name: .v}}]
      end;
  # only real packages: entries without a version (e.g. Trivy lists
  # requirements.txt itself) are not dependencies
  .components = [ (.components // [])[] | select((.version // "") != "") | normalise_licences ]'

for s in "${SBOMS[@]}"; do
  jq "$NORMALISE" "$DIR/$s" > "$WORK/$(basename "$s")"
done

# --- policy for this app: ignore the app itself and the Go standard library ----
root_names=$(for s in "${SBOMS[@]}"; do jq -r '.metadata.component.name // empty' "$DIR/$s"; done | sort -u)
{ cat "$POLICY"; echo; echo "# added by check-licenses.sh for this run"; echo "ignore-packages:"
  for n in $root_names "poc-$APP" stdlib std; do echo "  - \"$n\""; done
} | grep -v '^ignore-packages: \[\]' > "$WORK/policy.yaml"

# grant exits 1 on any violation; --dry-run keeps it 0 so all results are collected
docker run --rm --security-opt label=disable --user "$(id -u):$(id -g)" \
  -v "$PWD/$WORK":/w -w /w "$GRANT_IMAGE" -c policy.yaml check --dry-run \
  $(for s in "${SBOMS[@]}"; do basename "$s"; done) -o json > "$OUT" 2> /dev/null

# --- statuses ------------------------------------------------------------------
# grant marks licences it recognises as SPDX with a detailsUrl; anything else
# ("BSD-like", "Apache 2.0", classifier text) is not machine-readable.
STATUS='
  def status:
    if .decision == "allow" then "allowed"
    elif .decision == "ignore" then "ignored"
    elif ((.licenses // []) | length) == 0 then "unknown"
    elif ([.licenses[] | select((.detailsUrl // "") != "")] | length) > 0 then "violation"
    elif ([.licenses[].id | select(test("GPL"; "i"))] | length) > 0 then "violation"
    else "unknown" end;'

echo "## Licences ($APP)"
echo
echo "Policy: \`$POLICY\` (allow-list). Checked: dependency SBOMs (source, native) and image **app** views. OS packages are not checked."
echo
echo "| SBOM | Packages | Allowed | Violations | Unknown | Ignored | Result |"
echo "|---|---|---|---|---|---|---|"
jq -r "$STATUS"'
  .run.targets[] | .source.ref as $ref
  | [.evaluation.findings.packages[]? | status] as $s
  | ($s | map(select(. == "violation")) | length) as $v
  | ($s | map(select(. == "unknown")) | length) as $u
  | "| `\($ref)` | \($s | length) | \($s | map(select(. == "allowed")) | length) | \($v) | \($u) | \($s | map(select(. == "ignored")) | length) | \(
      if ($s | length) == 0 then "warning: no packages" elif $v > 0 then "FAIL: violation" elif $u > 0 then "warning: incomplete data" else "pass" end) |"' "$OUT"
echo
echo "<details><summary>Violations and unknowns per SBOM</summary>"
echo
jq -r "$STATUS"'
  .run.targets[] | .source.ref as $ref
  | [.evaluation.findings.packages[]? | {name, version, st: status, lic: ([.licenses[]?.id] | join(" OR "))}
     | select(.st == "violation" or .st == "unknown")] as $p
  | select(($p | length) > 0)
  | "**`\($ref)`**", "",
    ($p | sort_by(.st, .name)[] | "- \(if .st == "violation" then "**violation**" else "unknown" end) `\(.name)@\(.version)`: \(if .lic == "" then "_no licence_" else .lic end)"),
    ""' "$OUT"
echo "</details>"
echo

if [[ "${LICENSE_GATE:-0}" == "1" ]] && jq -e "$STATUS"'
    [.run.targets[] | select(.source.ref == "native-build.cdx.json")
     | .evaluation.findings.packages[]? | status | select(. == "violation")] | length > 0' "$OUT" > /dev/null; then
  echo "FAIL [$APP]: licence violation in the native SBOM" >&2
  exit 1
fi
