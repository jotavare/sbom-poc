# Which files belong to which package, from Syft's native JSON (syft-json).
# Shared by runtime-sbom.sh (files used -> packages) and unmanaged-files.sh
# (files no package claims).
#
# Ownership sources:
#   - "contains" relationships (OS packages: dpkg/apk/rpm file lists)
#   - the file list in Python package metadata (relative to site-packages)
#   - package locations (binaries, JARs, lock/manifest files)
#   - npm package directories (the folder of each package.json)
# usrmerge: Debian/Ubuntu make /lib a link to /usr/lib, so a file can appear
#   as /lib/x or /usr/lib/x: both forms are normalised to /usr/lib/x.

def usrmerge: sub("^/(?<d>lib|lib64|bin|sbin)/"; "/usr/\(.d)/");

def normpath: split("/") | reduce .[] as $p ([];
    if $p == "" or $p == "." then . elif $p == ".." then .[:-1] else . + [$p] end)
  | "/" + join("/") | usrmerge;

# [{id, purl, name, version, type, files: [paths], dirs: [path prefixes], vpaths}]
# A JAR nested in a fat JAR (Syft virtualPath "/srv/app.jar:BOOT-INF/lib/x.jar")
# does not own the outer file: opening the fat JAR doesn't mean x.jar was used.
# Its vpaths are matched against the JVM's class-load log instead.
def artifact_ownership:
  (.files // [] | map({key: .id, value: (.location.path | normpath)}) | from_entries) as $filePath
  | (.artifactRelationships // [] | map(select(.type == "contains"))
      | group_by(.parent) | map({key: .[0].parent, value: [.[].child]}) | from_entries) as $owns
  | [ .artifacts[] as $a
      | (($a.metadata.virtualPath // "") | contains(":")) as $nested
      | (if $nested then [] else [$a.locations[]? | .path | normpath] end) as $locs
      | {id: $a.id, purl: $a.purl, name: $a.name, version: $a.version, type: $a.type,
         files: ( $locs
                + [($owns[$a.id] // [])[] | $filePath[.] // empty]
                + (if $a.metadata.sitePackagesRootPath then
                     [$a.metadata.files[]?.path | ($a.metadata.sitePackagesRootPath + "/" + .) | normpath]
                   else [] end) | unique),
         # npm packages own their whole directory (package.json is the only location
         # Syft records), e.g. node_modules/express/ or /opt/yarn-v1.22.22/
         vpaths: [$a.metadata.virtualPath // empty],
         dirs: (if $a.type == "npm" then [$locs[] | select(endswith("/package.json")) | sub("package\\.json$"; "")]
                else [] end) } ];
