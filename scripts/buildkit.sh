#!/usr/bin/env bash
# Shared BuildKit helpers, sourced by build-image.sh, generate-sbom.sh and the
# Makefile's test target. Every build of an app runs on ONE BuildKit builder
# (poc-builder), so its stages are built once and reused: before, the tests and
# the native-SBOM/Maven exports used Docker's default builder and the runtime
# image a separate BuildKit builder, so dependencies were downloaded and
# compiled twice.
#
# Images leave BuildKit through the local registry (push, then pull), never via
# `docker build --output type=local`, which hung on GitHub runners.
#
# Usage (sourced): bk_ensure <out-root>; bk_build <app> <target> [--push <tag>] [extra buildx args...]

BK_REGISTRY_PORT="${REGISTRY_PORT:-5055}"
BK_REGISTRY="localhost:$BK_REGISTRY_PORT"
BK_REGISTRY_IMAGE="registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
BK_BUILDKIT_IMAGE="moby/buildkit:buildx-stable-1@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe"
BK_BUILDER="poc-builder"

# Start the local registry and the BuildKit builder once (parallel-safe).
bk_ensure() {
  local root="${1:-sbom}"
  mkdir -p "$root/.cache"
  (
    flock 9
    if [[ "$(docker inspect -f '{{.State.Running}}' poc-registry 2> /dev/null)" != "true" ]]; then
      docker rm -f poc-registry > /dev/null 2>&1 || true
      docker run -d --name poc-registry --restart unless-stopped \
        -p "127.0.0.1:$BK_REGISTRY_PORT:5000" "$BK_REGISTRY_IMAGE" > /dev/null
    fi
    if ! docker buildx inspect "$BK_BUILDER" > /dev/null 2>&1; then
      local cfg="$root/.cache/buildkitd.toml"
      printf '[registry."%s"]\n  http = true\n  insecure = true\n' "$BK_REGISTRY" > "$cfg"
      # host network: the builder reaches the registry on localhost
      docker buildx create --name "$BK_BUILDER" --driver docker-container \
        --driver-opt "network=host,image=$BK_BUILDKIT_IMAGE" --buildkitd-config "$cfg" > /dev/null
    fi
  ) 9> "$root/.cache/infra.lock"
}

# bk_build <app> <target> [--pull-as <local tag>] [extra buildx args...]
#   Without --pull-as: build only (e.g. the test stage; the result stays in the
#   builder's cache). With --pull-as: push to the local registry, pull it back
#   and tag it locally, so `docker run/create/save` can use it.
bk_build() {
  local app="$1" target="$2"; shift 2
  local local_tag=""
  if [[ "${1:-}" == --pull-as ]]; then local_tag="$2"; shift 2; fi
  if [[ -z "$local_tag" ]]; then
    docker buildx build --builder "$BK_BUILDER" --progress=plain --target "$target" "$@" "apps/$app"
    return
  fi
  local remote="$BK_REGISTRY/${local_tag%%:*}:${local_tag#*:}"
  docker buildx build --builder "$BK_BUILDER" --progress=plain --target "$target" \
    -t "$remote" --push "$@" "apps/$app" \
  && docker pull -q "$remote" > /dev/null \
  && docker tag "$remote" "$local_tag"
}
