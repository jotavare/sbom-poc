#!/usr/bin/env bash
# Vulnerability gate: fails if scan-vulns.sh's verdict was "fail" (critical/high
# with a fix not accepted, or a planted CVE no scanner found). Runs after the
# summary, so the report is always written first.
#
# Usage: scripts/vuln-gate.sh <app> [out-root]
set -euo pipefail
APP="${1:?usage: vuln-gate.sh <app> [out-root]}"
ROOT="${2:-sbom}"
status="$ROOT/$APP/vulns/gate.status"
[[ -s "$status" ]] || { echo "error: $status missing (make vulns APP=$APP)" >&2; exit 1; }
if [[ "$(cat "$status")" == pass ]]; then
  echo "vulnerability gate ($APP): pass"
else
  sed -n '/^### Gate/,$p' "$ROOT/$APP/reports/vulns.md"
  echo "error: vulnerability gate ($APP): $(cat "$status")" >&2
  exit 1
fi
