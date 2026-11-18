# SARIF 2.1.0 (OASIS standard) from scan-vulns.sh's merged findings (gate.json):
# one result per package + vulnerability, whichever scanners and SBOMs found it,
# so a viewer (GitHub code scanning, or any SARIF viewer) shows each finding once.
#
# Usage: jq -L scripts --arg app <app> --argjson accept <accept list>
#          --argjson files <{type: {uri, lines}}> -f scripts/vulns-sarif.jq gate.json
#   files maps a package type to the file that declares it (requirements.txt,
#   pom.xml…; "deb" -> the Dockerfile), so each result points at a real line.
# Only critical, high and medium findings are included; low ones stay in the report.

include "vulns";

def score: {"critical": "9.5", "high": "8.0", "medium": "5.5"}[.] // "2.0";
def level: if . == "critical" or . == "high" then "error" elif . == "medium" then "warning" else "note" end;
def help_uri: if startswith("CVE-") then "https://nvd.nist.gov/vuln/detail/\(.)"
  elif startswith("GHSA-") then "https://github.com/advisories/\(.)"
  else "https://osv.dev/vulnerability/\(.)" end;

# "pypi/flask@2.0.3" -> type "pypi", name "flask" (version dropped from the end)
def ptype: split("/")[0];
def pname: sub("^[^/]+/"; "") | sub("@[^@/]*$"; "");
def pversion: capture("@(?<v>[^@/]*)$").v // "";

# the line in the declaring file to point at (1-based); first line if not found
def find_line($lines; $needle): ([$lines | to_entries[] | select(.value | ascii_downcase | contains($needle | ascii_downcase)) | .key + 1] | first) // 1;
def needle: (. | ptype) as $t | (. | pname) as $n
  | if $t == "pypi" then "\($n)=="
    elif $t == "npm" then "\"node_modules/\($n)\""
    elif $t == "maven" then "<artifactId>\($n | split("/") | last)</artifactId>"
    elif $t == "cargo" then "name = \"\($n)\""
    elif $t == "golang" then ($n | if . == "stdlib" then "go " else . end)
    else "AS runtime" end;

[.[] | select(.sev | IN("critical", "high", "medium"))] as $f
| {
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [{
    tool: {driver: {
      name: "sbom-vulns",
      informationUri: "https://github.com/jotavare/sbom-poc",
      version: "1.0.0",
      rules: ($f | group_by(.id) | map({
        id: .[0].id,
        name: .[0].id,
        shortDescription: {text: "\(.[0].id) in \([.[].pkg | pname] | unique | join(", "))"},
        helpUri: (.[0].id | help_uri),
        properties: {"security-severity": (max_by(.sev | sev_rank) | .sev | score),
                     tags: ["security", "vulnerability", "sbom"]}}))}},
    results: ($f | sort_by(-(.sev | sev_rank), .pkg, .id) | map(. as $x
      | ($files[$x.pkg | ptype] // $files.deb) as $file
      | ([$accept[] | select(.key == $x.accepted)][0]) as $acc
      | {
        ruleId: .id,
        level: (.sev | level),
        message: {text: ([
          "\(.pkg | pname) \(.pkg | pversion) (\(.pkg | ptype)): \(.id), \(.sev) (rated by \(.sev_source // "scanner")).",
          (if .fixed then "Fixed in: \(if (.fix | length) > 0 then (.fix | join(", ")) else "a newer version" end)\(if .major_upgrade then " (a newer major version)" else "" end)." else "No fix yet." end),
          (if .kev then "In CISA KEV (actively exploited)." else empty end),
          (if .runs == true then "The package ran (runtime SBOM)." elif .runs == false then "The package did not run (runtime SBOM)." else empty end),
          (if .epss then "EPSS \(.epss * 1000 | round / 10)%." else empty end),
          "Severity by scanner: \(.sevs // {} | to_entries | map("\(.key) \(.value)") | join(", ")).",
          "Found by: \(.scanners | join(", ")) on \(.pairs | map(split("@")[1]) | unique | join(", ")).",
          (if $acc then "Accepted until \($acc.expires): \($acc.reason)." else empty end)
        ] | join(" "))},
        locations: [{physicalLocation: {
          artifactLocation: {uri: $file.uri},
          region: {startLine: find_line($file.lines; $x | .pkg | needle)}}}],
        properties: {package: .pkg, severity: .sev, scanners: .scanners, ran: .runs, kev: .kev, accepted: .accepted}}
        # accepted risks are suppressed (SARIF 2.1.0 3.35), not shown as open
        + (if $acc then {suppressions: [{kind: "external", status: "accepted",
             justification: "Accepted until \($acc.expires): \($acc.reason)"}]} else {} end)
      ))
  }]
}
