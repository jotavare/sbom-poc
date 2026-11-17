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
[[ "$APP" == java ]] && EXTRA_ENV=(-e "JAVA_TOOL_OPTIONS=-Xlog:class+load=info:file=/trace/classload.log")

docker rm -f "$NAME" > /dev/null 2>&1 || true
log "starting under strace: ${ARGV[*]}"
# -f follow children, -qq quiet; open/openat/execve(at) only.
# The trace goes to stderr (unbuffered) and is read back with `docker logs`:
# with -o <file>, strace buffers the file and the tail was lost on container stop.
docker run -d --name "$NAME" --security-opt label=disable \
  -p 127.0.0.1::8080 -v "$(cd "$STRACE_DIR" && pwd)/strace":/opt/strace:ro \
  -v "$(cd "$WORK" && pwd)":/trace "${EXTRA_ENV[@]}" \
  --entrypoint /opt/strace "$IMAGE" \
  -f -qq -e trace=open,openat,openat2,execve,execveat -e signal=none \
  -- "${ARGV[@]}" > /dev/null
trap 'docker rm -f "$NAME" > /dev/null 2>&1 || true' EXIT

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
probe_results=()
while read -r method path body; do
  [[ -z "${method:-}" || "$method" == \#* ]] && continue
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" ${body:+--data "$body"} \
              -H 'Content-Type: application/json' "$BASE$path" || true)
  probe_results+=("$method $path -> $code")
done < "$PROBES"
sleep 2
docker stop -t 10 "$NAME" > /dev/null
docker logs "$NAME" > "$WORK/strace.log" 2>&1 || true   # strace lines + the app's own output

# --- files actually used ---------------------------------------------------------------
# strace lines: <pid> openat(AT_FDCWD, "/path", ...) = 3   /   <pid> execve("/path", [...]) = 0
# Keep only SUCCESSFUL calls (result >= 0; failed lookups like ENOENT are not use),
# then normalise paths ("/usr/local/bin/../lib/x" -> "/usr/local/lib/x").
# (the first process's lines carry no PID prefix; children's do)
grep -E '^(\[?(pid +)?[0-9]+\]? +)?(open|openat|openat2|execve|execveat)\(' "$WORK/strace.log" \
  | grep -E '\) += [0-9]+( |$)' \
  | grep -oE '(open|openat|openat2|execve|execveat)\((AT_FDCWD, )?"[^"]+"' \
  | sed -E 's/^[a-z0-9]+\((AT_FDCWD, )?"//; s/"$//' | grep '^/' \
  | awk '{ n = split($0, p, "/"); k = 0
           for (i = 2; i <= n; i++) { if (p[i] == "" || p[i] == ".") continue
             if (p[i] == "..") { if (k > 0) k--; continue } out[++k] = p[i] }
           s = ""; for (i = 1; i <= k; i++) s = s "/" out[i]; print (s == "" ? "/" : s) }' \
  | sort -u > "$WORK/files.txt"
# Java: JARs that classes were loaded from (nested JARs inside the fat JAR)
if [[ -s "$WORK/classload.log" ]]; then
  grep -oE 'source: jar:file:[^ ]+' "$WORK/classload.log" | sed -E 's|^source: jar:file:||; s|!/$||; s|!/|:|' \
    | sort -u > "$WORK/jars.txt"
else
  : > "$WORK/jars.txt"
fi

# --- map files to packages (Syft ownership + package locations) -----------------------
# Ownership sources: "contains" relationships (OS packages), the file list in
#   Python metadata (relative to site-packages), package locations (binaries,
#   JARs), and npm package directories.
# usrmerge: Debian/Ubuntu make /lib a link to /usr/lib, so a file may be opened
#   as /lib/x/libc.so.6 but owned as /usr/lib/x/libc.so.6: both sides normalised.
jq -n --rawfile files "$WORK/files.txt" --rawfile jars "$WORK/jars.txt" --slurpfile s "$SYFT_JSON" '
  def usrmerge: sub("^/(?<d>lib|lib64|bin|sbin)/"; "/usr/\(.d)/");
  def normpath: split("/") | reduce .[] as $p ([];
      if $p == "" or $p == "." then . elif $p == ".." then .[:-1] else . + [$p] end)
    | "/" + join("/") | usrmerge;
  ($files | split("\n") | map(select(. != "") | usrmerge)) as $used
  | ($jars  | split("\n") | map(select(. != ""))) as $jarsUsed
  | ($used | map({key: ., value: true}) | from_entries) as $usedSet
  | ($s[0].files // [] | map({key: .id, value: (.location.path | normpath)}) | from_entries) as $filePath
  | ($s[0].artifactRelationships // [] | map(select(.type == "contains"))
      | group_by(.parent) | map({key: .[0].parent, value: [.[].child]}) | from_entries) as $owns
  | [ $s[0].artifacts[] as $a
      | ([$a.locations[]? | .path | normpath]) as $locs
      | ( [($owns[$a.id] // [])[] | $filePath[.] // empty]
        + (if $a.metadata.sitePackagesRootPath then
             [$a.metadata.files[]?.path | ($a.metadata.sitePackagesRootPath + "/" + .) | normpath]
           else [] end) ) as $owned
      | ($locs | map(select(test("/node_modules/")) | sub("/package\\.json$"; "/"))) as $npmDirs
      | ( [$locs[], $owned[] | select($usedSet[.])]
        + [$used[] as $u | $npmDirs[] | select(. as $d | $u | startswith($d)) | $u]
        + [$jarsUsed[] as $j | $locs[] as $l | select($j == $l or ($j | endswith($l))) | $j]
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
  echo "_Limits: only code paths exercised by the probes are seen. Go/Rust binaries are statically linked, so all their modules count as used once the binary runs._"
  echo
} > "$DIR/reports/runtime.md"

log "ok: $(jq '.components | length' "$DIR/runtime.cdx.json") of $(jq '[.components[]? | select(.purl)] | length' "$IMAGE_SBOM") packages used"
