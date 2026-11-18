# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# maven:3.9-eclipse-temurin-17 pinned by digest (2026-11-17)
FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 AS base
WORKDIR /src
COPY pom.xml .
# Download every dependency once and keep a copy for SBOM tools (`maven-repo` stage).
# The native SBOM is generated here too (cyclonedx-maven-plugin, see `sbom` stage),
# which also puts the plugin into the exported repo so cdxgen can run it offline.
# It writes CycloneDX 1.6 (plugin 2.9.3's maximum) and resolves pom.xml before
# the sources are copied: it lists the resolved dependencies, not the built JAR.
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline \
    && mvn -B -q org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom \
         -DoutputFormat=json -DoutputName=bom -DoutputDirectory=/sbom-native -DincludeTestScope=false \
         -DschemaVersion=1.6 \
    && cp -r /root/.m2/repository /m2-repository
COPY src ./src

# --- maven-repo stage: exports the resolved Maven repository so SBOM tools can
#     resolve pom.xml offline (scripts/generate-sbom.sh), instead of each tool
#     downloading hundreds of POMs from Maven Central (which rate-limits: HTTP 429)
FROM scratch AS maven-repo
COPY --from=base /m2-repository /

# --- test stage: `mvn test` ---
FROM base AS test
RUN --mount=type=cache,target=/root/.m2 mvn -B -q test

# --- build stage: Spring Boot fat JAR (dependencies nested in BOOT-INF/lib) ---
FROM base AS build
RUN --mount=type=cache,target=/root/.m2 mvn -B -q package -DskipTests

# --- sbom stage: native OWASP generator (cyclonedx-maven-plugin, run in `base`):
#     Maven's own resolved dependency tree, runtime scopes only (no test deps)
FROM base AS sbom
RUN cp /sbom-native/bom.json /native-build.cdx.json

# --- sbom-export: copied out by scripts/generate-sbom.sh (docker create + docker cp)
FROM scratch AS sbom-export
COPY --from=sbom /native-build.cdx.json /

# --- runtime stage (default): distroless JRE, no shell, non-root ---
# gcr.io/distroless/java17-debian13:nonroot pinned by digest (2026-11-17)
FROM gcr.io/distroless/java17-debian13:nonroot@sha256:b0719fc18858c53530b7301c25fa410075f0fdc442a78d3ee1786d1984075404 AS runtime
WORKDIR /srv
COPY --from=build /src/target/poc-java.jar ./poc-java.jar
USER nonroot:nonroot
EXPOSE 8080
# No shell for a curl-style check: the app checks itself (App.main "healthcheck")
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/usr/bin/java", "-jar", "/srv/poc-java.jar", "healthcheck"]
ENTRYPOINT ["/usr/bin/java", "-jar", "/srv/poc-java.jar"]
