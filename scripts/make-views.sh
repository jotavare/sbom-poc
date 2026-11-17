#!/usr/bin/env bash
# Derives OS and app VIEWS from each image SBOM. The full image SBOM stays the
# source of truth (it describes the artifact and is what gets signed); views
# only filter it, so different policies and owners can apply to each part:
#   os:  distro packages (deb/apk/rpm). GPL is normal here; fixed by base image
#        updates; owned by whoever maintains the platform.
#   app: language packages (pypi/npm/golang/maven/cargo/...). The licence policy
#        applies; fixed by dependency bumps; owned by the developers.
#   Everything else (files, interpreters as generic/..., the image itself) is in
#   neither view; the counts are recorded in the view metadata.
#
# Usage: scripts/make-views.sh <app> [out-root]
# Output: <out-root>/<app>/views/<gen>-image-{os,app}.cdx.json
set -euo pipefail
export LC_ALL=C

APP="${1:?usage: $0 <app> [out-root]}"
DIR="${2:-sbom}/$APP"
mkdir -p "$DIR/views"

OS_TYPES='^pkg:(deb|apk|rpm|alpm)/'
APP_TYPES='^pkg:(pypi|npm|golang|maven|cargo|gem|nuget|composer|hex|pub|swift|cocoapods|conan|cran|hackage)/'

for f in "$DIR"/*-image.cdx.json; do
  [[ -e "$f" ]] || continue
  gen="$(basename "$f" -image.cdx.json)"
  for view in os app; do
    re=$([[ $view == os ]] && echo "$OS_TYPES" || echo "$APP_TYPES")
    jq --arg re "$re" --arg view "$view" --arg src "$(basename "$f")" '
      def keep: (.purl // "") | test($re);
      ([.components[]? | select(keep)]) as $kept
      | ($kept | map(.["bom-ref"]) | map(select(. != null))) as $refs
      | .components = $kept
      | .dependencies = [ (.dependencies // [])[]
                          | select(.ref as $r | $refs | index($r))
                          | .dependsOn = [ (.dependsOn // [])[] | select(. as $d | $refs | index($d)) ] ]
      | .metadata.properties = ((.metadata.properties // []) + [
          {name: "poc:view", value: $view},
          {name: "poc:view:source", value: $src}])
    ' "$f" > "$DIR/views/$gen-image-$view.cdx.json"
  done
done
