# Local equivalents of the CI pipeline. Requires Docker and jq.
#
#   make <target> APP=<app>   one app (default: python)
#   make <target>-all         every app under apps/
#
SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c

APPS        := $(sort $(notdir $(wildcard apps/*)))
APP         ?= python
IMAGE        = poc-$(APP):local
SBOM_DIR    ?= sbom
REPORT      ?= $(SBOM_DIR)/SBOM-REPORT.md
ACTIONLINT  ?= rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

# Host port per app; every app listens on 8080 inside its container
PORT_python := 8001
PORT_node   := 8002
PORT_go     := 8003
PORT_java   := 8004
PORT_rust   := 8005
PORT         = $(or $(PORT_$(APP)),8000)

.PHONY: help apps port check-app test build run stop sbom runtime unmanaged scancode pipeline sbom-compare validate licenses quality \
        summary test-all build-all sbom-all stop-all report lint infra-down clean

help: ## Show targets
	@echo "Usage: make <target> [APP=<app>]   apps: $(APPS)"
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-13s %s\n", $$1, $$2}'

apps: ## List apps and their local ports
	@for a in $(APPS); do printf '  %-8s http://127.0.0.1:%s\n' "$$a" "$$(make -s port APP=$$a)"; done

port:
	@echo $(PORT)

check-app:
	@[[ -f apps/$(APP)/Dockerfile ]] || { echo "Unknown APP=$(APP). Choose one of: $(APPS)" >&2; exit 1; }

# --- one app ------------------------------------------------------------------
test: check-app ## Run the app's tests (Dockerfile `test` stage, on the shared BuildKit builder)
	@bash -c 'source scripts/buildkit.sh && bk_ensure $(SBOM_DIR) && bk_build $(APP) test'

build: check-app ## Build with BuildKit (+ SBOM & provenance attestations), push to the local registry, pull back as poc-<app>:local
	bash scripts/build-image.sh $(APP) $(SBOM_DIR)

run: build ## Run the app on 127.0.0.1:<port> (localhost only: it is vulnerable!)
	-@docker rm -f poc-$(APP) >/dev/null 2>&1
	docker run -d --name poc-$(APP) -p 127.0.0.1:$(PORT):8080 $(IMAGE)
	@echo "poc-$(APP) -> http://127.0.0.1:$(PORT)/health"

stop: ## Stop the app
	-@docker rm -f poc-$(APP) >/dev/null 2>&1 || true

sbom: build ## Generate source/build/image SBOMs (Syft, Trivy, cdxgen, native, BuildKit) and check them
	bash scripts/generate-sbom.sh $(APP) $(SBOM_DIR)
	bash scripts/check-sbom.sh $(APP) $(SBOM_DIR)

runtime: ## Runtime SBOM: run the image under strace, send probes, keep packages actually used (after make sbom)
	bash scripts/runtime-sbom.sh $(APP) $(SBOM_DIR)

unmanaged: ## Executables/libraries in the image that no package claims (SBOM blind spots)
	bash scripts/unmanaged-files.sh $(APP) $(SBOM_DIR)

scancode: build ## One-off: ScanCode licences + copyrights of the app's dependencies (slow)
	bash scripts/scancode.sh $(APP) $(SBOM_DIR)

validate: ## Validate every SBOM against its spec; writes sbom/<app>/reports/validation.md
	@mkdir -p $(SBOM_DIR)/$(APP)/reports
	bash scripts/validate-sbom.sh $(APP) $(SBOM_DIR) > $(SBOM_DIR)/$(APP)/reports/validation.md
	@cat $(SBOM_DIR)/$(APP)/reports/validation.md

pipeline: sbom runtime unmanaged validate summary ## Everything for one app: SBOMs, runtime SBOM, validation, reports

sbom-compare: ## Compare the generators for the app (run `make sbom` first)
	@SBOM_ROOT=$(SBOM_DIR) bash scripts/compare-sbom.sh $(APP)

licenses: ## Check dependency licences against policy/licenses.yaml (grant)
	@bash scripts/check-licenses.sh $(APP) $(SBOM_DIR)

quality: ## Score every SBOM of the app (sbomqs)
	@bash scripts/score-sbom.sh $(APP) $(SBOM_DIR)

summary: ## Write sbom/<app>/reports/summary.md: all results organised by SBOM stage
	@mkdir -p $(SBOM_DIR)/$(APP)/reports
	@bash scripts/summary.sh $(APP) $(SBOM_DIR) > $(SBOM_DIR)/$(APP)/reports/summary.md
	@echo "wrote $(SBOM_DIR)/$(APP)/reports/summary.md"

# --- every app ----------------------------------------------------------------
test-all: ## Run the tests of every app
	@for a in $(APPS); do $(MAKE) --no-print-directory test APP=$$a; done

build-all: ## Build every app
	@for a in $(APPS); do $(MAKE) --no-print-directory build APP=$$a; done

sbom-all: ## Full pipeline for every app (parallel-safe: make -j sbom-all)
	@$(MAKE) --no-print-directory --output-sync=target $(addprefix sbom-app-,$(APPS))

sbom-app-%:
	@$(MAKE) --no-print-directory pipeline APP=$*

stop-all: ## Stop every app
	@for a in $(APPS); do $(MAKE) --no-print-directory stop APP=$$a; done

report: ## Combine every app's summary.md into sbom/SBOM-REPORT.md (stamped with commit + tool versions)
	@bash scripts/report-header.sh $(SBOM_DIR) > $(REPORT)
	@for a in $(APPS); do f=$(SBOM_DIR)/$$a/reports/summary.md; [[ -s $$f ]] && { cat $$f; echo; } >> $(REPORT); done; true
	@echo "wrote $(REPORT)"

# --- repo ---------------------------------------------------------------------
lint: ## Lint GitHub Actions workflows
	docker run --rm --security-opt label=disable -v "$(CURDIR)":/repo:ro -w /repo $(ACTIONLINT) -color

infra-down: ## Remove the local registry and BuildKit builder
	-docker rm -f poc-registry
	-docker buildx rm poc-builder

clean: stop-all ## Stop apps and delete generated SBOMs
	rm -rf $(SBOM_DIR)
