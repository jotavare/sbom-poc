# syntax=docker/dockerfile:1
# --- rust-tools stage: prebuilt, checksum-verified cargo plugins (static musl
#     builds from the projects' GitHub releases) instead of `cargo install`,
#     which compiled them from source on every CI run (~1-3 min).
#     alpine because its tar handles .tar.xz (the slim Rust image has no xz).
# alpine:3.22 pinned by digest (2026-11-17)
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS rust-tools
ADD --checksum=sha256:7676443367c5e33d9fb22acef63cccb5e9202de12dae1b0579995eb3e2bc7a18 \
    https://github.com/rust-secure-code/cargo-auditable/releases/download/v0.7.7/cargo-auditable-x86_64-unknown-linux-musl.tar.xz /tmp/
ADD --checksum=sha256:528be9dd99ae522c3ee14fb881fd0cbf51767e8f12b74248f437e6a66b1a3c1b \
    https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-0.5.10/cargo-cyclonedx-x86_64-unknown-linux-musl.tar.xz /tmp/
RUN mkdir /out && for f in /tmp/*.tar.xz; do tar -xJf "$f" -C /tmp; done \
    && mv /tmp/cargo-auditable-*/cargo-auditable /tmp/cargo-cyclonedx-*/cargo-cyclonedx /out/

# rust:1-slim-bookworm pinned by digest (2026-11-17)
FROM rust:1-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS base
# cargo-auditable embeds the dependency list into the binary, so SBOM tools
# can see the crates inside a compiled Rust binary (otherwise it's opaque).
# cargo-cyclonedx is the native OWASP SBOM generator (`sbom` stage).
COPY --from=rust-tools /out/cargo-auditable /out/cargo-cyclonedx /usr/local/cargo/bin/
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo fetch --locked

# --- test stage: `cargo test` ---
FROM base AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo test --locked

# --- build stage: release binary with embedded dependency info ---
FROM base AS build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo auditable build --release --locked && cp target/release/poc-rust /poc-rust

# --- sbom stage: native OWASP generator (cargo-cyclonedx) from Cargo metadata
FROM base AS sbom
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo cyclonedx --format json --spec-version 1.7 --override-filename native-build.cdx \
    && cp native-build.cdx.json /native-build.cdx.json

# --- sbom-export: copied out by scripts/generate-sbom.sh (docker create + docker cp)
FROM scratch AS sbom-export
COPY --from=sbom /native-build.cdx.json /

# --- runtime stage (default): distroless with glibc, no shell, non-root ---
# gcr.io/distroless/cc-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS runtime
COPY --from=build /poc-rust /poc-rust
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/poc-rust", "healthcheck"]
ENTRYPOINT ["/poc-rust"]
