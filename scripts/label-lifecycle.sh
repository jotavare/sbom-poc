#!/usr/bin/env bash
# Records WHEN each SBOM was generated, in the standard field of its format
# (CISA 2025 minimum element "Generation Context"; see docs/SBOM-TYPES.md):
#
#   file name        CISA type   CycloneDX metadata.lifecycles   SPDX 3 software_sbomType
#   *-source.*       Source      pre-build                       source
#   native-build.*   Build       build                           build
#   *-image.*        Analyzed    post-build                      analyzed
#   runtime.*        Runtime     operations                      runtime
#
# We orchestrate the generators, so we are the SBOM author and declare the
# context. If a tool already set a different lifecycle (cdxgen labels image scans
# "pre-build,post-build"), its value is kept in the property poc:tool-lifecycles.
# SPDX 2.3 has no field for this, so .spdx.json files are left unchanged.
#
# Usage: scripts/label-lifecycle.sh <app> [out-root]
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"

stage_of() {  # file name -> "cdx-phase spdx3-type"
  case "$(basename "$1")" in
    *-source.*)     echo "pre-build source" ;;
    native-build.*) echo "build build" ;;
    *-image.*)      echo "post-build analyzed" ;;
    runtime.*)      echo "operations runtime" ;;
    *)              echo "" ;;
  esac
}

shopt -s nullglob
for f in "$DIR"/*.cdx.json; do
  read -r phase _ <<< "$(stage_of "$f")"
  [[ -n "$phase" ]] || continue
  jq --arg phase "$phase" '
    ([.metadata.lifecycles[]?.phase // empty] | join(",")) as $tool
    | .metadata.lifecycles = [{phase: $phase}]
    | if ($tool != "" and $tool != $phase) then
        .metadata.properties = ((.metadata.properties // []) + [{name: "poc:tool-lifecycles", value: $tool}])
      else . end' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done

for f in "$DIR"/*.spdx3.json; do
  read -r _ type <<< "$(stage_of "$f")"
  [[ -n "$type" ]] || continue
  jq --arg t "$type" '
    (if has("@graph") then .["@graph"] else [] end) as $g
    | if ($g | any(.type == "software_Sbom")) then
        .["@graph"] |= map(if .type == "software_Sbom" then .software_sbomType = [$t] else . end)
      else . end' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done
