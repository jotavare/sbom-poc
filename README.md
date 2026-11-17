# SBOM PoC

A proof of concept for software supply-chain transparency, built around **five small, deliberately vulnerable apps** (Python, Node.js, Go, Java, Rust). Iteration 1 covers **SBOMs end to end**: every SBOM stage the standards define, five generators, validation, licences, quality, and what actually runs. Iteration 2 **scans those SBOMs for vulnerabilities** with three scanners and gates the build. Later iterations add one class of security check each (secrets, SAST, signing, DAST…).

> **Warning: every app in `apps/` is intentionally insecure** (injection flaws, SSRF, unsafe deserialization, weak crypto, old dependencies with known CVEs). Run them on localhost only. Never deploy them.

**Docs**
- [`docs/SBOM-TYPES.md`](docs/SBOM-TYPES.md): the SBOM stages (CISA types, CycloneDX lifecycles, CISA 2025 minimum elements, BSI TR-03183-2), with quotes and sources
- [`docs/SECURITY-CHECKS.md`](docs/SECURITY-CHECKS.md): catalogue of all security check types, tool options, and what this PoC covers
- `sbom/SBOM-REPORT.md`: the generated report (`make report`; CI artifact `sbom-report`), organised by stage, stamped with commit, tool versions and image digests. Not committed, so it can't drift from the code.

## Iteration log

| # | Iteration | Status |
|---|---|---|
| 1 | Apps + SBOMs for all 4 stages (source, build, image, runtime) + validation, licences, quality, graph, blind spots | done |
| 2 | SBOM vulnerability scan (Grype, Trivy, OSV-Scanner) + gate on critical/high with a fix; distroless images | done |
| 3 | Secrets scanning (Gitleaks or TruffleHog) | proposed |
| 4 | SAST (Semgrep / Opengrep) | proposed |
| 5 | Dockerfile + CI hardening (Hadolint, zizmor, actionlint) | proposed |
| 6 | Container image scan | proposed |
| 7 | Signing + SBOM attestation + provenance (Cosign) | proposed |
| 8 | DAST (ZAP baseline, Nuclei) | proposed |
| 9 | Dependency-Track, VEX, … | proposed |

## The SBOM stages

An SBOM's content depends on **when** it's made. CISA defines SBOM types; CycloneDX records the stage in `metadata.lifecycles`; CISA's 2025 minimum elements make this "Generation Context" mandatory; BSI TR-03183-2 requires SBOMs to contain the information available during the build. Details and quotes: [`docs/SBOM-TYPES.md`](docs/SBOM-TYPES.md).

| # | Stage (CISA / CycloneDX) | Question | Files in `sbom/<app>/` | Made by |
|---|---|---|---|---|
| 1 | Source / `pre-build` | What does the repo declare? | `syft-source.*`, `trivy-source.*`, `cdxgen-source.*` | scanners on `apps/<app>/` |
| 2 | Build / `build` | What did the build resolve? | `native-build.cdx.json`; `buildkit-image.spdx.json` + `buildkit-provenance.json` | the language's own OWASP generator inside the Docker build; BuildKit's attestation |
| 3 | Analyzed / `post-build` | What is in the image? | `syft-image.*`, `trivy-image.*`, `cdxgen-image.*`, `views/*-image-{os,app}.cdx.json` | scanners on the built image |
| 4 | Runtime / `operations` | What actually runs? | `runtime.cdx.json` | the app run under strace while probes exercise it |

**Formats:** `.cdx.json` CycloneDX **1.7** (Java's Maven plugin: 1.6, its maximum), `.spdx.json` SPDX 2.3, `.spdx3.json` **SPDX 3.0.1** (Syft, cdxgen; Trivy and BuildKit don't support it yet).

## Quick start

Requirements: Docker (with buildx), `make`, `jq`.

```bash
make help                    # all targets
make pipeline APP=node       # everything for one app (the CI job): build, SBOMs, runtime, unmanaged, validate, vulns, summary, gate
make -j3 sbom-all            # the same for every app, in parallel
make report                  # combine all app summaries into sbom/SBOM-REPORT.md

make test APP=go             # the app's tests (Dockerfile test stage)
make run  APP=node           # start one app on 127.0.0.1:<port> (make apps lists ports)
make build APP=java          # BuildKit build + SBOM/provenance attestations, local registry, digest
make sbom APP=java           # stage 1-3 SBOMs + checks
make runtime APP=java        # stage 4: runtime SBOM (after make sbom)
make unmanaged APP=java      # files in the image no package claims
make validate APP=java       # schema validation (cyclonedx-cli, pyspdxtools, spdx3-validate)
make vulns APP=java          # vulnerability scan of the SBOMs (Grype, Trivy, OSV-Scanner)
make vuln-gate APP=java      # fail on critical/high with a fix that isn't accepted
make sbom-compare APP=java   # generator comparison + dependency graph
make licenses APP=java       # licence policy (grant)
make quality APP=java        # SBOM quality scores (sbomqs)
make scancode APP=java       # one-off: declared vs detected licences, copyrights (slow)
make summary APP=java        # everything above into sbom/java/reports/summary.md, by stage

make clean                   # stop apps, delete sbom/
make infra-down              # remove the local registry + BuildKit builder
```

## Workflow

**Pipeline map:** https://jotavare.github.io/sbom-poc/ (the four SBOM stages, every CI step with its tools and outputs, where results go). Source: [`site/index.html`](site/index.html), published by [`pages.yml`](.github/workflows/pages.yml) on every change. The Pages site is public, although this repository is private.

- CI ([`sbom.yml`](.github/workflows/sbom.yml)) runs **the same `make` targets** as local runs. Tools run as containers or binaries pinned by digest or checksum; actions pinned by commit SHA; read-only token; runner pinned to `ubuntu-26.04` (hosted runner images can't be pinned by digest).
- Every tool call has a timeout and its own log (uploaded with the artifacts).
- ScanCode ([`scancode.yml`](.github/workflows/scancode.yml)) runs only by hand: it's slow and a one-off analysis.

## The apps

| App | Stack | Runtime image | What's interesting for SBOMs | Port |
|---|---|---|---|---|
| [`python`](apps/python) | Flask 2.0.3, gunicorn | distroless `python3` (Debian 13, Python 3.13) | `requirements.txt` with every transitive dep pinned; a venv built with Debian's own Python, copied into distroless | 8001 |
| [`node`](apps/node) | Express 4.17.1 | distroless `nodejs24` | 4 direct deps become 65 installed; no npm, corepack or yarn in the image | 8002 |
| [`go`](apps/go) | `net/http` | distroless `static` | Static binary: tools read the module list **embedded in the binary** | 8003 |
| [`java`](apps/java) | Spring Boot 2.6.1, Log4j 2.14.1 | distroless `java17` | Fat JAR with **nested JARs**; `pom.xml` needs Maven to resolve | 8004 |
| [`rust`](apps/rust) | tiny_http | distroless `cc` | Binary built with **`cargo auditable`**, which embeds the crate list | 8005 |

Each planted flaw is tagged `VULN:` in the code: Log4Shell (`java`), PyYAML `yaml.load` (`python`), lodash prototype pollution and `eval` (`node`), user-controlled regex on regex 1.5.4 (`rust`), dgrijalva/jwt-go (`go`), plus command injection and SSRF in every app.

### App contract

```
apps/<app>/
  Dockerfile              stages: base, test, sbom + sbom-export (native Build SBOM), runtime (last, non-root)
                          java also: maven-repo (resolved deps, for offline SBOM scans)
  sbom-expect.txt         package URLs every SBOM must contain (the vulnerable markers)
  sbom-reject.txt         packages that must NOT ship: dev/test deps (optional)
  sbom-expect-skip.txt    documented exceptions: "<sbom file> <purl|*> <reason>" (optional)
  sbom-invalid-ok.txt     known generator bugs that fail validation: "<file> <reason>"
  vuln-expect.txt         planted CVEs the scanners must find: "<CVE> <note>"
  vuln-accept.txt         accepted risks for the gate: "<package | prefix* | ID> <expires> <reason>"
  runtime-probes.txt      requests sent while recording the runtime SBOM
  scancode-paths.txt      paths in the image ScanCode scans (python, node, java)
  .dockerignore
```

Every app listens on **8080** in its container and serves `GET /health`. **Every runtime image is distroless** (`gcr.io/distroless/*-debian13:nonroot`): no shell, no package manager, non-root. Build tools stay in the build stages. Base images are pinned by digest and every dependency to an exact version. To add an app: follow the contract, add a port in the `Makefile` and a matrix entry in the workflows.

## Generators

| Generator | Stages | Formats | How it runs |
|---|---|---|---|
| [Syft](https://github.com/anchore/syft) | source, image | CycloneDX 1.7, SPDX 2.3, SPDX 3.0.1 | pinned container; image scan adds SHA-1/256/512 file digests |
| [Trivy](https://github.com/aquasecurity/trivy) | source, image | CycloneDX 1.7, SPDX 2.3 | pinned container, persistent DB cache |
| [cdxgen](https://github.com/cdxgen/cdxgen) (OWASP) | source, image | CycloneDX 1.7, SPDX 3.0.1 | checksum-pinned release binary; source scan inside the app's build image (real toolchain); image scan with `--network none` |
| Native OWASP generators | build | CycloneDX 1.7 (Java 1.6) | `cyclonedx-py`, `cyclonedx-npm`, `cyclonedx-gomod`, `cyclonedx-maven-plugin`, `cargo-cyclonedx` inside the Docker build |
| BuildKit `--sbom=true` | build (attestation) | SPDX 2.3 | attached to the image digest with SLSA provenance |

**Security:** no tool gets the Docker socket (images are scanned from a `docker save` tarball); the runtime SBOM needs no extra privileges; downloaded tools are checksum-pinned (strace's source tarball was verified against its maintainer's PGP signature first).

> **Why the cdxgen release binary?** The official image (`ghcr.io/cdxgen/cdxgen`) is ~16.6 GB (a full build machine on AlmaLinux 10) and needs an x86-64-v3/AVX2 CPU. The 183 MB release binary is what cdxgen's README recommends for CI. Gotchas: it unpacks itself to `/tmp` (must allow exec) and needs `libatomic.so.1` (shipped next to it, so app images stay unchanged).

## Checks

| Check | What fails or is reported |
|---|---|
| `check-sbom.sh` (fails the build) | missing generator output, image without digest or BuildKit attestation, a CycloneDX SBOM without a stage, a missing vulnerable marker (unless excused with a reason), a **dev/test dependency in what ships**, an image SBOM without OS packages |
| `scan-vulns.sh` + `vuln-gate.sh` (fails the build) | a critical/high vulnerability **with a fix** in the image (union of 3 scanners × 3 image SBOMs) that isn't accepted in `vuln-accept.txt` (accepts expire), or a planted CVE no scanner finds. Report: scanner × SBOM matrix, agreement, planted CVEs, fix-first list (KEV, ran at runtime, severity, EPSS) |
| `validate-sbom.sh` (fails the build) | invalid CycloneDX (`cyclonedx-cli`), SPDX 2.3 (`pyspdxtools`), SPDX 3.0.1 (`spdx3-validate` schema + SHACL; large files: official JSON schema with `jsonschema-rs`). Known generator bugs are shown as warnings |
| Comparison + graph | packages found by each generator (after normalising spelling), dependency graph vs `native-build` |
| Licences (`grant`) | dependency licences vs [`policy/licenses.yaml`](policy/licenses.yaml): violation / unknown / ignored, after normalising licence expressions |
| Quality (`sbomqs`) | scores per format, NTIA/CISA 2026, BSI v2.1, FSCT; missing minimum elements listed |
| Runtime | packages that ship vs packages that ran |
| Unmanaged files | executables/libraries no package claims (SBOM blind spots) |
| ScanCode (one-off) | declared licence vs licences detected in the files; copyright holders |

## Findings so far

**Generators disagree, mostly on edges.** After normalising spelling (Debian epochs, `+`/`%2b`, Go `v` prefixes, PEP 503 names) and leaving out dev/test scope, image SBOMs agree almost completely (python 102/102 packages, node 299/300, java 179/181). Real differences that remain:
- **Java source:** Syft lists only the 4 direct deps from `pom.xml`; Trivy resolves the full tree.
- **Rust image:** cdxgen can't read `cargo auditable` data; Syft and Trivy can.
- **Go:** only the native generator lists the Go standard library in source SBOMs.

**Dependency graphs differ much more than package lists** (links that the package manager's own `native-build` SBOM also has):

| App | Syft | Trivy | cdxgen |
|---|---|---|---|
| node | links present, but none from the app (0 direct deps) | 101/101 | 101/101 (+ dev deps marked optional) |
| java | 0/60 | 60/60 | 29/60 |
| python | no graph (`requirements.txt` is flat); only native has 12 links | | |

**Most of what ships never ran, so every image is now distroless** (runtime SBOM, before → after the switch):

| App | Language packages used | OS packages used |
|---|---|---|
| python | 13 / 15 (`pip`, `packaging` unused) | 3 / 87 → **5 / 38** |
| node | 69 / 214 → **67 / 68** (the 145 unused were exactly npm + corepack from the slim image) | 2 / 88 → **4 / 14** |
| java | 30 / 31 (class-loading log) | 2 / 140 → **3 / 25** |
| go, rust | all (static binaries: compiled-in modules count as used) | 0 / 6, 2 / 14 (distroless from the start) |

Distroless also removes the shell: the planted command injection (`sh -c "ping …"`) is still in the code, and SAST will find it, but in the running containers it can't start a shell.

**Blind spots:** with `python:3.12-slim`, CPython was compiled into `/usr/local`: 119 files of its standard library and `libpython` belonged to no package. Distroless Python comes from Debian packages, so that blind spot is gone: what's left in every image is `ca-certificates.crt` (generated at build time) and one motd script.

**Licences:** after normalising expressions, python has one real violation (`chardet`, **LGPL**); node now passes, since the npm it shipped (Artistic-2.0) is gone. cdxgen and Trivy both write `jakarta.annotation-api`'s dual licence wrong; the native generator gets it right. ScanCode found licences metadata doesn't declare: **Werkzeug ships Ubuntu font files** (Ubuntu Font Licence, CC-BY) for its debugger page.

**Formats and validation:** BuildKit's SPDX 2.3 lacks the SHA-1 file checksums SPDX 2.3 requires; Syft's and cdxgen's SPDX 3.0.1 fail the official SHACL shapes (all recorded as known generator bugs). Syft's digest setting must be comma-separated: with spaces it silently dropped SHA-256 and broke its SPDX 2.3.

**Vulnerabilities (iteration 2): the SBOM you scan decides what you find.** Three scanners on three image SBOMs of the same image (python, findings):

| SBOM | Grype | Trivy | OSV-Scanner |
|---|---|---|---|
| Syft's | **351** | 40 | 41 |
| Trivy's | 40 | **351** | 41 |
| cdxgen's | 157 | 40 | **163** |

- **OS packages only match in the scanner's own family.** Debian publishes advisories per *source* package (`krb5`), SBOMs list binary packages (`libgssapi-krb5-2`). Trivy records the source in its own property, Syft in a purl qualifier (`upstream=`), cdxgen not at all; each scanner reads only its own way. OSV-Scanner reads Debian packages only with `distro=debian-13` (cdxgen), not `debian-13.7` (Syft, Trivy). Language packages match everywhere: the purl is enough.
- So the gate takes the **union** of all scanners on all image SBOMs. Every planted CVE (Log4Shell, Spring4Shell, PyYAML, lodash…) is found by all three scanners, except on cdxgen's Rust SBOM (cdxgen can't read `cargo auditable` data).
- **False positives:** OSV-Scanner reads Syft's Go stdlib version `go1.27.4` instead of the purl's `1.27.4` and reports all 164 Go stdlib advisories since 2021.
- **Prioritising:** java has 133 critical/high findings, 101 in packages that actually ran (runtime SBOM) and 6 in CISA KEV; most Debian findings have no fix yet, so they're reported, not gated.
- **The gate found a real one:** `pip` shipped in the Python venv with a fixable high CVE, and the runtime SBOM showed it never runs, so it's removed instead of accepted. Everything else blocking is planted and accepted until 2027-05-17.

## Speed

Full CI run: about 7 minutes for all five apps, vulnerability scan included (Java, the slowest: 439 s).

| Change | Effect |
|---|---|
| All builds on one shared BuildKit builder (`scripts/buildkit.sh`) | tests, image and SBOM-stage builds reuse each other's layers instead of downloading and compiling twice (Java's generate step 214 s → 136 s) |
| Static strace cached by its Dockerfile hash | runtime SBOM step 60–70 s → 3–11 s (building strace was almost all of it) |
| Validation batched: one container per validator | instead of ~20 container starts per app |
| Trivy DB cache keyed by day | Java's ~920 MB saved once a day, not every run |
| Vulnerability DBs (Grype ~3 GB, Trivy) shared by the three scanners, cached by day; scanners run in parallel | vulnerability step 90–140 s → 25–45 s (+ 30–55 s cache restore) |
| cdxgen release binary, no tool image | the first CI run had hung 10+ min on `docker build --output type=local`; that pattern is no longer used anywhere |
| `jsonschema-rs` for large SPDX 3 files | Java's validation: ~24 min → seconds |
| Persistent Trivy cache (+ `actions/cache`) | Trivy's Java DB downloaded once (was ~190 s per scan) |
| Prebuilt, checksum-verified Rust tools | no compiling cargo plugins per run |
| Offline Maven repo for Java | no Maven Central rate limits (HTTP 429) |
| Syft `--enrich` only for source scans | node: 55 s saved |
| Timeouts + a log per tool call | a hang fails fast and names itself |

## Layout

```
apps/<app>/                the five vulnerable apps (see App contract)
scripts/
  build-image.sh           BuildKit build + attestations, local registry, image digest
  generate-sbom.sh         stages 1-3: Syft, Trivy, cdxgen, native
  label-lifecycle.sh       stage (lifecycle) on every SBOM
  make-views.sh            OS / app views of image SBOMs
  check-sbom.sh            checks that fail the build
  runtime-sbom.sh          stage 4: runtime SBOM (strace + probes)
  unmanaged-files.sh       files no package claims
  validate-sbom.sh         spec validation (+ spdx3_schema_check.py)
  scan-vulns.sh            vulnerability scan of the SBOMs (vulns.jq normalises findings)
  vuln-gate.sh             the vulnerability gate
  compare-sbom.sh          generator comparison + graph (graph.jq)
  check-licenses.sh        licence normalisation + policy (grant)
  score-sbom.sh            quality per format (sbomqs)
  scancode.sh              one-off licence/copyright scan
  summary.sh               per-app report by stage
  report-header.sh         report stamp + how to read it
  ownership.jq             file -> package ownership (runtime, unmanaged)
tools/                     strace-static, scancode (built from pinned sources)
policy/licenses.yaml       licence allow-list
docs/                      SBOM types, security-checks catalogue
site/                      pipeline map (GitHub Pages)
.github/workflows/         sbom.yml (every push), scancode.yml (manual), pages.yml (site/)
sbom/                      generated output (git-ignored)
```
