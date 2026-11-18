#!/usr/bin/env bash
# Runtime SBOM (CISA type "Runtime", CycloneDX lifecycle "operations"): which of
# the packages that SHIP in the image are actually USED while the app runs.
#
# How:
#   1. Run the app's normal image (same user, env, working dir, command), but
#      start its process under a static strace (tools/strace-static) that logs
#      every file successfully opened or executed. Java additionally logs which
#      JARs its classes are loaded from (-Xlog:class+load), because classes
#      inside a fat JAR are read without separate file opens.
#   2. Send the requests in apps/<app>/runtime-probes.txt.
#   3. Map the files to packages with Syft's file-ownership data for the same
#      image (sbom/.cache/<app>/syft-image.syft.json, from generate-sbom.sh).
#
# Limits (also stated in the report):
#   - Only code paths the probes exercise are seen; untested paths look unused.
#   - Statically linked binaries (Go, Rust): executing the binary "uses" every
#     module compiled into it; syscall tracing can't tell modules apart.
#
# Usage: scripts/runtime-sbom.sh <app> [out-root]
# Output: <out-root>/<app>/runtime.cdx.json, reports/runtime.md, reports/runtime/*.log
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
OUT_ROOT="${2:-sbom}"
DIR="$OUT_ROOT/$APP"
IMAGE="${IMAGE:-poc-$APP:local}"
PROBES="apps/$APP/runtime-probes.txt"
SYFT_JSON="$OUT_ROOT/.cache/$APP/syft-image.syft.json"
IMAGE_SBOM="$DIR/syft-image.cdx.json"
STRACE_TAG="poc-strace:7.3"
STRACE_DIR="$OUT_ROOT/.cache/strace-7.3"
WORK="$DIR/reports/runtime"
NAME="poc-runtime-$APP"
log() { echo "==> [$APP] runtime: $*"; }

for f in "$PROBES" "$SYFT_JSON" "$IMAGE_SBOM"; do
  [[ -s "$f" ]] || { echo "error: missing $f (run make sbom APP=$APP first)" >&2; exit 1; }
done
mkdir -p "$WORK" "$STRACE_DIR"
rm -f "$WORK"/*.log

# --- static strace (built once, parallel-safe) --------------------------------------
(
  flock 9
  if [[ ! -x "$STRACE_DIR/strace" ]]; then
    log "building static strace (tools/strace-static)"
    docker build -q --target strace -t "$STRACE_TAG" tools/strace-static > /dev/null
    cid=$(docker create "$STRACE_TAG" /none)
    docker cp -q "$cid:/strace" "$STRACE_DIR/strace"
    docker rm "$cid" > /dev/null
  fi
) 9> "$OUT_ROOT/.cache/strace.lock"

# --- run the app under strace --------------------------------------------------------
mapfile -t ARGV < <(docker image inspect "$IMAGE" \
  --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}}' \
  | jq -r -s '(.[0] // []) + (.[1] // []) | .[]')
(( ${#ARGV[@]} > 0 )) || { echo "error: $IMAGE has no entrypoint/cmd" >&2; exit 1; }

chmod 777 "$WORK"   # the app runs as its own non-root user and writes the trace here
EXTRA_ENV=()
# one log per JVM (%p = pid), no rotation: a second JVM (e.g. a health check)
# must not overwrite the app's log
[[ "$APP" == java ]] && EXTRA_ENV=(-e "JAVA_TOOL_OPTIONS=-Xlog:class+load=info:file=/trace/classload-%p.log::filecount=0")

docker rm -f "$NAME" > /dev/null 2>&1 || true
log "starting under strace: ${ARGV[*]}"
# -f follow children, -qq quiet; open/openat/execve(at) only.
# The trace goes to stderr (unbuffered) and is read back with `docker logs`:
# with -o <file>, strace buffers the file and the tail was lost on container stop.
# --no-healthcheck: the image's HEALTHCHECK runs a separate process (Java: a
# second JVM) that is not the app; the trace and the class-load log are the app's
docker run -d --name "$NAME" --security-opt label=disable --no-healthcheck \
  -p 127.0.0.1::8080 -v "$(cd "$STRACE_DIR" && pwd)/strace":/opt/strace:ro \
  -v "$(cd "$WORK" && pwd)":/trace "${EXTRA_ENV[@]}" \
  --entrypoint /opt/strace "$IMAGE" \
  -f -qq -e trace=open,openat,openat2,execve,execveat -e signal=none \
  -- "${ARGV[@]}" > /dev/null
TMP="$(mktemp -d)"
trap 'docker rm -f "$NAME" > /dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

PORT=$(docker port "$NAME" 8080/tcp | head -1 | sed 's/.*://')
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 1 90); do
  curl -fsS -o /dev/null "$BASE/health" 2> /dev/null && break
  [[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" == true ]] \
    || { docker logs "$NAME" 2>&1 | tail -20 >&2; echo "error: app exited" >&2; exit 1; }
  sleep 1
done
curl -fsS -o /dev/null "$BASE/health" || { echo "error: app not healthy after 90s" >&2; exit 1; }

log "sending probes ($PROBES)"
# Probe lines: "METHOD PATH [BODY]", optionally " | Header: value". An HTTP error
# is recorded, not a failure (e.g. /ping needs a shell the distroless image
# doesn't have); no response at all means the app died, which fails the step.
probe_results=(); no_response=0
while IFS= read -r line; do
  [[ -z "${line// /}" || "$line" == \#* ]] && continue
  hdr=(); if [[ "$line" == *" | "* ]]; then hdr=(-H "${line#* | }"); line="${line%% | *}"; fi
  read -r method path body <<< "$line"
  code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -X "$method" ${body:+--data "$body"} \
              -H 'Content-Type: application/json' "${hdr[@]}" "$BASE$path" || true)
  [[ "$code" == 000 ]] && no_response=$((no_response + 1))
  probe_results+=("$method $path -> $code")
done < "$PROBES"
(( no_response == 0 )) || { printf '%s\n' "${probe_results[@]}" >&2; echo "error: $no_response probe(s) got no response" >&2; exit 1; }
sleep 2
docker stop -t 10 "$NAME" > /dev/null
docker logs "$NAME" > "$WORK/strace.log" 2>&1 || true   # strace lines + the app's own output

# --- files actually used ---------------------------------------------------------------
# strace lines: <pid> openat(AT_FDCWD, "/path", ...) = 3   /   <pid> execve("/path", [...]) = 0
# Keep only SUCCESSFUL calls (result >= 0; failed lookups like ENOENT are not use),
# then normalise paths ("/usr/local/bin/../lib/x" -> "/usr/local/lib/x").
# (the first process's lines carry no PID prefix; children's do)
# A call interrupted by another process is split by strace into
# "<call>(... <unfinished ...>" and, later, "<... call resumed>) = N": join them
# per process first, or such calls are lost.
awk '{
  pid = ""; if (match($0, /^\[pid +[0-9]+\]/) || match($0, /^[0-9]+ /)) pid = substr($0, RSTART, RLENGTH)
  if ($0 ~ / <unfinished \.\.\.>$/) { l = $0; sub(/ <unfinished \.\.\.>$/, "", l); pend[pid] = l; next }
  if ($0 ~ /<\.\.\. [a-z0-9_]+ resumed>/ && (pid in pend)) {
    r = $0; sub(/^.*<\.\.\. [a-z0-9_]+ resumed>/, "", r); print pend[pid] r; delete pend[pid]; next }
  print }' "$WORK/strace.log" > "$TMP/strace-joined.log"
calls() {  # <syscall regex>: successful calls' paths, normalised
  grep -E "^(\[?(pid +)?[0-9]+\]? +)?($1)\(" "$TMP/strace-joined.log" \
    | grep -E '\) += [0-9]+( |$)' \
    | grep -oE "($1)\((AT_FDCWD, )?\"[^\"]+\"" \
    | sed -E 's/^[a-z0-9]+\((AT_FDCWD, )?"//; s/"$//' | grep '^/' \
    | awk '{ n = split($0, p, "/"); k = 0
             for (i = 2; i <= n; i++) { if (p[i] == "" || p[i] == ".") continue
               if (p[i] == "..") { if (k > 0) k--; continue } out[++k] = p[i] }
             s = ""; for (i = 1; i <= k; i++) s = s "/" out[i]; print (s == "" ? "/" : s) }' \
    | sort -u || true
}
calls 'open|openat|openat2|execve|execveat' > "$TMP/opened.txt"
calls 'execve|execveat' > "$TMP/executed.txt"

# The paths a process asks for are often symlinks (libsqlite3.so.0 ->
# libsqlite3.so.0.8.6), while package file lists name the real file: resolve
# every path through the image's symlinks. And a script's interpreter (#! line)
# is loaded by the kernel without an open() that strace sees: add it.
cid=$(docker create "$IMAGE" /none)
docker export "$cid" > "$TMP/rootfs.tar"
docker rm "$cid" > /dev/null
# GNU tar -tv symlink line: "lrwxrwxrwx 0/0 0 2026-01-01 00:00 usr/lib/x.so.1 -> x.so.1.2"
tar -tvf "$TMP/rootfs.tar" | awk '$1 ~ /^l/ { l = $0; sub(/^([^ ]+ +){5}/, "", l)
    i = index(l, " -> "); print "/" substr(l, 1, i - 1) "\t" substr(l, i + 4) }' \
  | sed 's|^//|/|' > "$TMP/symlinks.tsv"
RESOLVE='include "ownership";
  ($links | split("\n") | map(select(. != "") | split("\t") | {key: (.[0] | normpath), value: .[1]}) | from_entries) as $L
  | def ancestors: . as $p | [range(2; ($p | split("/") | length) + 1) as $i | $p | split("/")[0:$i] | join("/")];
    def step: . as $p | [ancestors[] | select($L[.])] | last as $a
      | if $a == null then $p
        else ($L[$a]) as $t
          | (if ($t | startswith("/")) then $t else ($a | sub("/[^/]*$"; "")) + "/" + $t end)
            + ($p | ltrimstr($a)) | normpath end;
    def resolve: reduce range(0; 10) as $i (.; step);
  $in | split("\n") | map(select(. != "")) | .[] | normpath | ., resolve'
jq -r -n -L "$(dirname "$0")" --rawfile links "$TMP/symlinks.tsv" --rawfile in "$TMP/executed.txt" "$RESOLVE" \
  | sort -u > "$TMP/executed-resolved.txt"
: > "$TMP/interpreters.txt"
while read -r exe; do
  line="$(tar -xOf "$TMP/rootfs.tar" "${exe#/}" 2> /dev/null | head -c 256 | head -1 | tr -d '\0' || true)"
  [[ "$line" == '#!'* ]] && awk '{print $1}' <<< "${line#\#!}" >> "$TMP/interpreters.txt"
done < "$TMP/executed-resolved.txt"
cat "$TMP/opened.txt" "$TMP/interpreters.txt" > "$TMP/raw.txt"
jq -r -n -L "$(dirname "$0")" --rawfile links "$TMP/symlinks.tsv" --rawfile in "$TMP/raw.txt" "$RESOLVE" \
  | sort -u > "$WORK/files.txt"
# Java: JARs that classes were loaded from, as "<fat jar>:<nested jar>"
# (e.g. /srv/poc-java.jar:BOOT-INF/lib/log4j-core-2.14.1.jar), one log per JVM
cat "$WORK"/classload*.log 2> /dev/null | grep -oE 'source: jar:file:[^ ]+' \
  | sed -E 's|^source: jar:file:||; s|!/$||; s|!/|:|' | sort -u > "$WORK/jars.txt" || true

# --- map files to packages (Syft ownership; see scripts/ownership.jq) ---------------------
jq -n -L "$(dirname "$0")" --rawfile files "$WORK/files.txt" --rawfile jars "$WORK/jars.txt" \
   --slurpfile s "$SYFT_JSON" '
  include "ownership";
  ($files | split("\n") | map(select(. != "") | usrmerge)) as $used
  | ($jars  | split("\n") | map(select(. != ""))) as $jarsUsed
  | ($used | map({key: ., value: true}) | from_entries) as $usedSet
  | [ $s[0] | artifact_ownership[] as $a
      | ( [$a.files[] | select($usedSet[.])]
        + [$used[] as $u | $a.dirs[] | select(. as $d | $u | startswith($d)) | $u]
        + [$jarsUsed[] as $j | $a.vpaths[] as $v | select($j == $v) | $j]
        ) as $evidence
      | select(($evidence | length) > 0)
      | {purl: $a.purl, name: $a.name, version: $a.version, type: $a.type,
         evidence: ($evidence | unique | .[0:5])} ]' > "$WORK/used-packages.json"

# --- runtime SBOM: the image SBOM, reduced to the packages that ran ---------------------
probes_json=$(printf '%s\n' "${probe_results[@]}" | jq -R . | jq -s .)
jq --slurpfile used "$WORK/used-packages.json" --argjson probes "$probes_json" '
  ($used[0] | map({key: .purl, value: .evidence}) | from_entries) as $ev
  | .metadata.lifecycles = [{phase: "operations"}]
  | .metadata.properties = ((.metadata.properties // [])
      + [{name: "poc:runtime:method", value: "strace (open/openat/execve) + Syft file ownership; Java: -Xlog:class+load"},
         {name: "poc:runtime:probes", value: ($probes | join("; "))}])
  | .components = [ .components[]? | select(.purl and $ev[.purl])
      | .evidence = ((.evidence // {}) + {occurrences: [$ev[.purl][] | {location: .}]}) ]
  | ([.components[]["bom-ref"]]) as $refs
  | .dependencies = [ (.dependencies // [])[] | select(.ref as $r | $refs | index($r))
      | .dependsOn = [ (.dependsOn // [])[] | select(. as $d | $refs | index($d)) ] ]
' "$IMAGE_SBOM" > "$DIR/runtime.cdx.json"

# --- report: ships vs runs ---------------------------------------------------------------
{
  echo "## Runtime SBOM ($APP): ships vs runs"
  echo
  echo "Image \`$IMAGE\` run under strace; probes: $(printf '`%s`, ' "${probe_results[@]}" | sed 's/, $//')."
  echo "Files opened/executed: $(wc -l < "$WORK/files.txt"); Java class-load JARs: $(wc -l < "$WORK/jars.txt")."
  echo
  echo "| Package type | Ships (image SBOM) | Runs (runtime SBOM) | Not used |"
  echo "|---|---|---|---|"
  jq -r --slurpfile rt "$DIR/runtime.cdx.json" '
    def ptype: (.purl // "") | capture("^pkg:(?<t>[^/]+)/").t // "other";
    ([.components[]? | select(.purl) | ptype] | group_by(.) | map({key: .[0], value: length}) | from_entries) as $ships
    | ([$rt[0].components[]? | ptype] | group_by(.) | map({key: .[0], value: length}) | from_entries) as $runs
    | $ships | keys[] as $t | "| `pkg:\($t)` | \($ships[$t]) | \($runs[$t] // 0) | \($ships[$t] - ($runs[$t] // 0)) |"' "$IMAGE_SBOM"
  echo
  echo "<details><summary>App packages that ship but were not used during the probes</summary>"
  echo
  jq -r --slurpfile rt "$DIR/runtime.cdx.json" '
    ([$rt[0].components[]?.purl]) as $ran
    | [.components[]? | select((.purl // "") | test("^pkg:(pypi|npm|maven|golang|cargo)/"))
       | select(.purl as $p | $ran | index($p) | not) | "\(.name)@\(.version)"] | sort
    | if length == 0 then "_none_" else map("`" + . + "`") | join(", ") end' "$IMAGE_SBOM"
  echo
  echo "</details>"
  echo
  echo "_Limits: only code paths exercised by the probes are seen. Go and Rust compile their modules/crates into the binary, so all of them count as used once it runs (\"ran\" means linked in, not called; Rust still loads glibc and libgcc dynamically). Java: a nested JAR counts as used only if classes were loaded from it._"
  echo
} > "$DIR/reports/runtime.md"

log "ok: $(jq '.components | length' "$DIR/runtime.cdx.json") of $(jq '[.components[]? | select(.purl)] | length' "$IMAGE_SBOM") packages used"
