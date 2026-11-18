# Normalises vulnerability scanner output (Grype, Trivy, OSV-Scanner JSON) to
# one finding per (package, vulnerability), so the scanners can be compared.
# Used by scan-vulns.sh as: jq -c --arg scanner <name> --arg sbom <file>
#   -L scripts 'include "vulns"; findings'
#
# Each finding:
#   {scanner, sbom, pkg, id, ids, sev, fix, fixed, epss, kev}
#   pkg   normalised purl without qualifiers ("pypi/pyyaml@5.3.1"), as in graph.jq
#   id    canonical ID: the lowest CVE among the IDs and aliases, else the first ID.
#         Scanners name the same flaw differently (Grype: GHSA-…, Trivy: CVE-…,
#         OSV: PYSEC-…), so comparing raw IDs would show false disagreements.
#   sev   critical | high | medium | low | unknown
#   epss  exploit probability (FIRST EPSS), Grype only
#   kev   in CISA's Known Exploited Vulnerabilities catalog, Grype only

include "graph";

# IDs a scanner reports without their CVE alias, with the evidence for the mapping
def aliases: {
  "NSWG-ECO-516": "CVE-2020-8203"   # lodash, Trivy; same report as npm advisory 1523 / GHSA-p6mc-m468-83gw
};

# OSV names distro records after the CVE ("DEBIAN-CVE-2024-1234"): use the CVE
def canon: map(sub("^[A-Z]+-(?<c>CVE-)"; "\(.c)")) | map(aliases[.] // .)
  | (map(select(startswith("CVE-"))) | sort | first) // (sort | first);

def sev_name: ascii_downcase | if . == "negligible" then "low"
  elif IN("critical", "high", "medium", "low") then . else "unknown" end;

# OSV gives a CVSS score ("9.8"), not a rating: map it with CVSS v3 ranges
def cvss_name: (tonumber? // null) as $s
  | if $s == null then "unknown" elif $s >= 9 then "critical" elif $s >= 7 then "high"
    elif $s >= 4 then "medium" elif $s > 0 then "low" else "unknown" end;

# src: a Debian SOURCE package (cdxgen lists them, "?arch=source", next to the
# binary packages); scan-vulns.sh moves such findings onto the binary packages
# built from that source, so one flaw is not counted twice.
def finding($ids; $sev; $fix; $fixed; $epss; $kev; $purl):
  {scanner: $ARGS.named.scanner, sbom: $ARGS.named.sbom,
   pkg: ($purl | norm_purl), src: ($purl | test("[?&]arch=source")),
   ids: ($ids | map(aliases[.] // .) | unique), id: ($ids | canon),
   sev: $sev, fix: ($fix | map(sub("^[<>=~^ ]+"; ""))), fixed: $fixed, epss: $epss, kev: $kev};

# version-aware sort key ("2.10" after "2.9")
def vkey: [scan("[0-9]+") | tonumber];

def grype:
  .matches[]? | select(.artifact.purl != null and .artifact.purl != "")
  | .vulnerability as $v
  | finding(([$v.id] + [.relatedVulnerabilities[]?.id]);
            ($v.severity // "" | sev_name);
            ($v.fix.versions // []);
            ($v.fix.state == "fixed");
            ([$v.epss[]?.epss] | max);
            (($v.knownExploited // []) | length > 0);
            .artifact.purl);

def trivy:
  .Results[]?.Vulnerabilities[]? | select(.PkgIdentifier.PURL != null)
  | finding([.VulnerabilityID];
            (.Severity // "" | sev_name);
            ((.FixedVersion // "") | split(", ") | map(select(. != "")));
            (.Status == "fixed" or ((.FixedVersion // "") != ""));
            null; null;
            .PkgIdentifier.PURL);

def osv:
  .results[]?.packages[]? | select(.package.purl != null) | . as $p
  | .groups[]? as $g
  | ([$p.vulnerabilities[]? | select(.id as $i | $g.ids | index($i))]) as $vs
  # fixed versions only from ranges for THIS package and ecosystem ("Debian:13",
  # not sid's), and not git commits
  | ([$vs[].affected[]? | select(.package.ecosystem == $p.package.ecosystem and .package.name == $p.package.name)
      | .ranges[]? | select(.type != "GIT") | .events[]?.fixed // empty] | unique) as $fix
  | finding(($g.aliases // $g.ids);
            ($g.max_severity // "" | cvss_name);
            $fix; ($fix | length > 0); null; null;
            $p.package.purl);

def findings:
  if $ARGS.named.scanner == "grype" then grype
  elif $ARGS.named.scanner == "trivy" then trivy
  else osv end;

def sev_rank: {"critical": 4, "high": 3, "medium": 2, "low": 1}[.] // 0;
