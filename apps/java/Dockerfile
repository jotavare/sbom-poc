# syntax=docker/dockerfile:1
# maven:3.9-eclipse-temurin-17 pinned by digest (2026-11-17)
FROM maven:3.9-eclipse-temurin-17@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 AS base
WORKDIR /src
COPY pom.xml .
# Download every dependency once and keep a copy for SBOM tools (`maven-repo` stage).
# The native SBOM is generated here too (cyclonedx-maven-plugin, see `sbom` stage),
# which also puts the plugin into the exported repo so cdxgen can run it offline.
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline \
    && mvn -B -q org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom \
         -DoutputFormat=json -DoutputName=bom -DoutputDirectory=/sbom-native -DincludeTestScope=false \
         -DschemaVersion=1.7 \
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

# --- runtime stage (default): JRE only, non-root ---
# eclipse-temurin:17-jre pinned by digest (2026-11-17); Ubuntu-based
FROM eclipse-temurin:17-jre@sha256:fb2cec8da84e3f086b59e29bf432d372e396fe0c247adcfb89303a28c2e313c0 AS runtime
WORKDIR /srv
COPY --from=build /src/target/poc-java.jar ./poc-java.jar
RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s CMD ["sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q ok <&3"]
ENTRYPOINT ["java", "-jar", "/srv/poc-java.jar"]
