# syntax=docker/dockerfile:1
# rust:1-slim-bookworm pinned by digest (2026-11-17)
FROM rust:1-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS base
# cargo-auditable embeds the dependency list into the binary, so SBOM tools
# can see the crates inside a compiled Rust binary (otherwise it's opaque).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-auditable --version 0.7.7 --locked
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
    cargo install cargo-cyclonedx --version 0.5.10 --locked \
    && cargo cyclonedx --format json --spec-version 1.5 --override-filename native-source.cdx \
    && cp native-source.cdx.json /native-source.cdx.json

# --- sbom-export: `docker build --target sbom-export --output type=local,dest=<dir>`
FROM scratch AS sbom-export
COPY --from=sbom /native-source.cdx.json /

# --- runtime stage (default): distroless with glibc, no shell, non-root ---
# gcr.io/distroless/cc-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS runtime
COPY --from=build /poc-rust /poc-rust
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/poc-rust", "healthcheck"]
ENTRYPOINT ["/poc-rust"]
