.PHONY: help list-images list-images-full check-dummy-shas verify-images verify-images-icsp verify-images-podman verify-images-arm64 verify-images-amd64 verify-images-ppc64le verify-images-s390x verify-release scan-release scan-cves scan-cves-icsp scan-cves-json scan-cves-json-icsp image-report clean-reports check-tools install-deps all-checks make-scripts-executable setup-release

# Configuration
export EXTRAS_DIR ?= extras
export REPORTS_DIR ?= reports
export TRIVY_SEVERITY ?= HIGH,CRITICAL
export TRIVY_FORMAT ?= table
export TRIVY_TIMEOUT ?= 10m
IMAGE_KEY ?=
RELEASE ?=

# Scripts directory
SCRIPTS_DIR := scripts

# Build scan_cves arguments
SCAN_ARGS := $(if $(IMAGE_KEY),--image-key $(IMAGE_KEY),)

# Helper to run setup-release if RELEASE is specified
define setup-if-release
	$(if $(RELEASE),@$(MAKE) setup-release RELEASE=$(RELEASE),)
endef

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-25s %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick commands for multi-release testing:"
	@echo "  make verify-release RELEASE=release-2.17    # Setup + verify a release"
	@echo "  make scan-release RELEASE=release-2.17      # Setup + scan a release"
	@echo ""
	@echo "CVE scanning options:"
	@echo "  make scan-cves                                        # Scan current extras/"
	@echo "  make scan-cves RELEASE=release-2.17                   # Setup + scan release"
	@echo "  make scan-cves IMAGE_KEY=multiclusterhub_operator     # Scan single component"
	@echo "  make scan-cves RELEASE=release-2.17 IMAGE_KEY=...     # Release + component"
	@echo "  make scan-cves TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM    # Custom severity"

list-images: ## List all images from extras/*.json files
	@python3 $(SCRIPTS_DIR)/list_images.py

list-images-full: ## List all images with full SHA digests
	@SHOW_FULL_DIGEST=true python3 $(SCRIPTS_DIR)/list_images.py

check-dummy-shas: ## Check for dummy or flagged SHA digests
	@python3 $(SCRIPTS_DIR)/check_dummy_shas.py

check-dummy-shas-warn: ## Check for dummy SHAs (warning only, for pre-GA)
	@WARN_ONLY=true python3 $(SCRIPTS_DIR)/check_dummy_shas.py

verify-images: ## Verify all images are pullable using skopeo
	@python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-icsp: ## Verify images using ICSP registry redirects (for pre-GA testing)
	@ICSP_CONFIG=icsp-config.json python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-podman: ## Verify images using podman (alternative to skopeo)
	@USE_PODMAN=true python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-arm64: ## Verify images for arm64 architecture
	@OVERRIDE_ARCH=arm64 OVERRIDE_OS=linux python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-amd64: ## Verify images for amd64 architecture
	@OVERRIDE_ARCH=amd64 OVERRIDE_OS=linux python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-ppc64le: ## Verify images for ppc64le architecture
	@OVERRIDE_ARCH=ppc64le OVERRIDE_OS=linux python3 $(SCRIPTS_DIR)/verify_images.py

verify-images-s390x: ## Verify images for s390x architecture
	@OVERRIDE_ARCH=s390x OVERRIDE_OS=linux python3 $(SCRIPTS_DIR)/verify_images.py

verify-release: setup-release verify-images ## Verify images for a release (Usage: make verify-release RELEASE=release-2.17)

scan-release: setup-release scan-cves-json-icsp ## Scan a release for CVEs (Usage: make scan-release RELEASE=release-2.17)

scan-cves: ## Scan all images for CVEs using Trivy (text output)
	$(setup-if-release)
	@python3 $(SCRIPTS_DIR)/scan_cves.py $(SCAN_ARGS)

scan-cves-icsp: ## Scan images using ICSP registry redirects (text output)
	$(setup-if-release)
	@ICSP_CONFIG=icsp-config.json python3 $(SCRIPTS_DIR)/scan_cves.py $(SCAN_ARGS)

scan-cves-json: ## Scan images and output results in JSON format
	$(setup-if-release)
	@OUTPUT_JSON=true python3 $(SCRIPTS_DIR)/scan_cves.py $(SCAN_ARGS)

scan-cves-json-icsp: ## Scan images with ICSP and output JSON (for Slack reports)
	$(setup-if-release)
	@ICSP_CONFIG=icsp-config.json OUTPUT_JSON=true python3 $(SCRIPTS_DIR)/scan_cves.py $(SCAN_ARGS)

image-report: ## Generate comprehensive image report
	@python3 $(SCRIPTS_DIR)/image_report.py

slack-cve-report: ## Send CVE scan summary to Slack (requires SLACK_WEBHOOK_URL)
	@python3 $(SCRIPTS_DIR)/slack_cve_report.py

slack-cve-report-detailed: ## Send detailed CVE report to Slack
	@SLACK_FORMAT=detailed python3 $(SCRIPTS_DIR)/slack_cve_report.py

setup-release: ## Set up extras/ from a release branch (Usage: make setup-release RELEASE=release-2.17)
	@bash $(SCRIPTS_DIR)/setup_release.sh $(RELEASE)

all-checks: check-dummy-shas verify-images image-report ## Run all verification checks (no CVE scan)
	@echo "All checks complete!"

full-scan: all-checks scan-cves ## Run all checks including CVE scanning
	@echo "Full scan complete!"

clean-reports: ## Remove all generated reports
	@echo "Removing reports directory..."
	@rm -rf $(REPORTS_DIR)
	@echo "Reports cleaned"

check-tools: ## Check if required tools are installed
	@echo "Checking required tools..."
	@command -v python3 >/dev/null 2>&1 && echo "✓ python3 found" || { echo "✗ python3 is not installed"; exit 1; }
	@python3 -c "import rich" 2>/dev/null && echo "✓ rich library found" || echo "⚠ rich not found - run: pip install -r requirements.txt"
	@command -v skopeo >/dev/null 2>&1 && echo "✓ skopeo found" || echo "⚠ skopeo not found (optional for verify-images)"
	@command -v podman >/dev/null 2>&1 && echo "✓ podman found" || echo "⚠ podman not found (optional for verify-images-podman)"
	@command -v trivy >/dev/null 2>&1 && echo "✓ trivy found" || echo "⚠ trivy not found (required for scan-cves)"
	@echo "Tool check complete"

install-deps: ## Install Python dependencies
	@echo "Installing Python dependencies..."
	@pip install -r requirements.txt
	@echo "Dependencies installed"

.PHONY: make-scripts-executable
make-scripts-executable: ## Make all scripts executable
	@chmod +x $(SCRIPTS_DIR)/*.py $(SCRIPTS_DIR)/*.sh
	@echo "Scripts are now executable"
