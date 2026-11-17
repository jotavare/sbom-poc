# Dependency-graph helpers for CycloneDX documents (used by compare-sbom.sh).

# Normalised package identity, matching compare-sbom.sh's packages():
# no qualifiers/subpath, lower case, no Debian epoch, "+" not "%2b", Go without
# "v" prefix and std -> stdlib, PyPI names per PEP 503.
def norm_purl:
  sub("[?#].*$"; "") | sub("^pkg:"; "") | gsub("%40"; "@") | gsub("%2[bB]"; "+")
  | sub("@[0-9]+(%3[aA]|:)"; "@") | sub("^golang/std@go"; "golang/stdlib@")
  | sub("^(?<p>golang/[^@]+)@v"; "\(.p)@") | ascii_downcase
  | if startswith("pypi/") then
      (split("@")) as $x | "pypi/" + ($x[0] | ltrimstr("pypi/") | gsub("[_.]"; "-")) + "@" + ($x[1] // "")
    else . end;

# Graph view of a document: refs, their purls/types, adjacency, the app root.
def graph:
  ([.. | objects | select(has("bom-ref"))] | map({key: .["bom-ref"], value: {purl: (.purl // null), type: (.type // ""), scope: (.scope // null)}}) | from_entries) as $nodes
  | ((.dependencies // []) | map({key: .ref, value: (.dependsOn // [])}) | from_entries) as $adj
  | {nodes: $nodes, adj: $adj, root: (.metadata.component["bom-ref"] // null)};

# A "package" for graph purposes: a library/framework with a purl, in runtime
# scope (cdxgen marks dev/test deps "optional"), and not the app itself (some
# tools list the app as a package, e.g. Trivy's pkg:maven/poc/poc-java).
def is_pkg($g): ($g.nodes[.] // {})
  | ((.type == "library" or .type == "framework") and .purl != null
     and ((.scope // "required") == "required")
     and ((.purl | test("/poc-[a-z]+(@|$)|devsecops-sbom-poc")) | not));

# Direct dependencies of the app: packages reached from the root, walking
# through non-package nodes (e.g. Trivy puts package.json between app and deps).
def direct($g):
  if $g.root == null then [] else
  [ $g.root ] | {todo: ., seen: {}, out: []}
  | until(.todo | length == 0;
      .todo[0] as $n | .todo |= .[1:]
      | if .seen[$n] then . else .seen[$n] = true
        | reduce ($g.adj[$n] // [])[] as $c (.;
            if ($c | is_pkg($g)) then .out += [$c] else .todo += [$c] end)
        end)
  | .out | unique end;

# All packages reachable from the app, with the maximum depth (direct = 1).
def reach($g):
  direct($g) as $d
  | {frontier: $d, seen: ($d | map({key: ., value: true}) | from_entries), depth: (if ($d | length) > 0 then 1 else 0 end)}
  | until(.frontier | length == 0;
      [ .frontier[] as $n | ($g.adj[$n] // [])[] | select(is_pkg($g)) ] as $next
      | .seen as $s
      | ([$next[] | select($s[.] | not)] | unique) as $new
      | .seen += ($new | map({key: ., value: true}) | from_entries)
      | .frontier = $new
      | if ($new | length) > 0 then .depth += 1 else . end)
  | {reachable: (.seen | keys | length), depth: .depth};

# Package-to-package edges as normalised "parent -> child" strings.
def pkg_edges($g):
  [ $g.adj | to_entries[] | .key as $p | select($p | is_pkg($g)) | .value[] | select(is_pkg($g))
    | (($g.nodes[$p].purl | norm_purl) + " -> " + ($g.nodes[.].purl | norm_purl)) ] | unique;

# One summary object per document.
def graph_metrics:
  graph as $g
  | (direct($g)) as $d
  | (reach($g)) as $r
  | {direct: ($d | length),
     direct_purls: [$d[] | $g.nodes[.].purl | norm_purl] | unique,
     reachable: $r.reachable, depth: $r.depth,
     edges: pkg_edges($g)};
