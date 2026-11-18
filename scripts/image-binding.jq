# Which exact field ties an image SBOM to the image in artifact.json?
# Each generator records the image differently; only these fields count (a
# digest mentioned anywhere else in the file proves nothing):
#   Syft    metadata.component.version = the manifest digest (set by generate-sbom.sh)
#   Trivy   property aquasecurity:trivy:ImageID = the config digest
#   cdxgen  property oci:image:manifest:Config = blobs/sha256/<config digest>
# Usage: jq --slurpfile a artifact.json -L scripts 'include "image-binding"; binding($a[0])' <image SBOM>
# Returns the matching field's name, or null.
def props: [.metadata.component.properties[]?, .metadata.properties[]?];
def binding($a):
  if (.metadata.component.version // "") == $a.manifest_digest then "metadata.component.version (manifest digest)"
  elif any(props[]; .name == "aquasecurity:trivy:ImageID" and .value == $a.config_digest) then "aquasecurity:trivy:ImageID (config digest)"
  elif any(props[]; .name == "oci:image:manifest:Config" and .value == ("blobs/sha256/" + ($a.config_digest | ltrimstr("sha256:")))) then "oci:image:manifest:Config (config digest)"
  else null end;
