# syntax=docker/dockerfile:1
# golang:1.27-bookworm pinned by digest (2026-11-17)
FROM golang:1.27-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS base
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

# --- test stage: `go vet` + `go test` ---
FROM base AS test
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./...

# --- build stage: static binary; module info stays embedded (SBOM tools read it) ---
FROM base AS build
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/poc-go .

# --- sbom stage: native OWASP generator (cyclonedx-gomod). `app` mode lists only
#     the modules compiled into the binary (+ Go stdlib), with licences detected
#     from module sources. The tool reads the main module's version from git, and
#     .git is not in the build context, so a throwaway repo is created here.
FROM base AS sbom
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    git init -q && git -c user.name=sbom -c user.email=sbom@localhost commit -q --allow-empty -m sbom \
    && go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0 \
      app -json -std -licenses -assert-licenses -main . -output /native-source.cdx.json

# --- sbom-export: `docker build --target sbom-export --output type=local,dest=<dir>`
FROM scratch AS sbom-export
COPY --from=sbom /native-source.cdx.json /

# --- runtime stage (default): distroless, no shell, non-root ---
# gcr.io/distroless/static-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS runtime
COPY --from=build /out/poc-go /poc-go
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/poc-go", "healthcheck"]
ENTRYPOINT ["/poc-go"]
