# Makefile Documentation

This document describes the available targets and usage patterns for the ACM operator bundle Makefile.

## Prerequisites

Before using the Makefile targets, ensure you have the required tools installed:

```bash
make check-tools
```

Required tools:
- `python3` - Required for all scripts (Note: The Makefile specifically uses `python3` command, not `python`)
- `skopeo` or `podman` - Required for image verification
- `trivy` - Required for CVE scanning
- `jq` - Useful for manual JSON inspection (optional)

Install Python dependencies:
```bash
make install-deps
```

Or manually:
```bash
pip3 install -r requirements.txt
```

Python dependencies:
- `rich>=13.0.0` - For formatted table output

## Configuration Variables

The following environment variables can be set to customize behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTRAS_DIR` | `extras` | Directory containing image manifest JSON files |
| `REPORTS_DIR` | `reports` | Output directory for generated reports |
| `TRIVY_SEVERITY` | `HIGH,CRITICAL` | CVE severity levels to report |
| `TRIVY_FORMAT` | `table` | Trivy output format (table, json, etc.) |
| `TRIVY_TIMEOUT` | `10m` | Timeout for Trivy scans |
| `IMAGE_KEY` | - | Specific image component to scan (optional) |
| `RELEASE` | - | Release branch to check out (optional) |

## Quick Start

Display available targets with descriptions:
```bash
make help
```

Run all verification checks (without CVE scanning):
```bash
make all-checks
```

Run complete verification including CVE scanning:
```bash
make full-scan
```

## Target Reference

### Information and Listing

#### `list-images`
List all container images from `extras/*.json` files with short digest format (12 characters, no "sha256:" prefix).

**Usage:**
```bash
make list-images
```

**Output format:**
- Displays compact table with status icon, image key, and short digest
- Status icons: `✓` for valid SHA, `…` for placeholder/dummy SHA (000000...)
- Digests shown as 12 hex characters: `331b906aaf8d`
- Summary shows total images, real SHAs, and placeholder count

**Example output:**
```
┃   ┃ Image Key              ┃ Digest       ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ ✓ │ console                │ 62612f2ef686 │
│ … │ acm_cli                │ 000000000000 │
```

#### `list-images-full`
List all images with complete SHA-256 digests (full 71-character format including "sha256:" prefix).

**Usage:**
```bash
make list-images-full
```

**Output format:**
- Displays full SHA-256 digests: `sha256:331b906aaf8d52a92eb095f6bd8eedf498f6f6a2e9dce0be8b04cfd0e3db07e9`
- Table width expands to accommodate complete 64-character hashes
- Useful for copying full digests or detailed verification

#### `help`
Display help message with all available targets and quick command examples.

**Usage:**
```bash
make help
```

### Image Validation

#### `check-dummy-shas`
Check for dummy or placeholder SHA digests in image manifests. Warns if dummy SHAs are found but does not fail the build.

**Usage:**
```bash
make check-dummy-shas
```

#### `verify-images`
Verify that all images are pullable using skopeo.

**Usage:**
```bash
make verify-images
```

#### `verify-images-icsp`
Verify images using ICSP (ImageContentSourcePolicy) registry redirects for pre-GA testing.

**Usage:**
```bash
make verify-images-icsp
```

Requires `icsp-config.json` in the repository root.

#### `verify-images-podman`
Verify images using podman instead of skopeo (alternative verification method).

**Usage:**
```bash
make verify-images-podman
```

### Architecture-Specific Verification

Verify images for specific CPU architectures:

#### `verify-images-amd64`
Verify images for AMD64/x86_64 architecture.

**Usage:**
```bash
make verify-images-amd64
```

#### `verify-images-arm64`
Verify images for ARM64/aarch64 architecture.

**Usage:**
```bash
make verify-images-arm64
```

#### `verify-images-ppc64le`
Verify images for PowerPC 64-bit Little Endian architecture.

**Usage:**
```bash
make verify-images-ppc64le
```

#### `verify-images-s390x`
Verify images for IBM Z mainframe architecture.

**Usage:**
```bash
make verify-images-s390x
```

### CVE Scanning

All CVE scanning targets use Trivy to scan container images for vulnerabilities.

#### `scan-cves`
Scan all images for CVEs with text output to console.

**Usage:**
```bash
# Scan current extras/ directory
make scan-cves

# Scan with custom severity levels
make scan-cves TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM

# Scan single component
make scan-cves IMAGE_KEY=multiclusterhub_operator

# Setup and scan a release
make scan-cves RELEASE=release-2.17
```

#### `scan-cves-icsp`
Scan images using ICSP registry redirects with text output.

**Usage:**
```bash
make scan-cves-icsp
make scan-cves-icsp RELEASE=release-2.17
```

#### `scan-cves-json`
Scan images and output results in JSON format.

**Usage:**
```bash
make scan-cves-json
make scan-cves-json IMAGE_KEY=multiclusterhub_operator
```

#### `scan-cves-json-icsp`
Scan images with ICSP redirects and output JSON (used for Slack reports).

**Usage:**
```bash
make scan-cves-json-icsp
make scan-cves-json-icsp RELEASE=release-2.17
```

### Release Management

#### `setup-release`
Check out and set up extras/ directory from a specific release branch.

**Usage:**
```bash
make setup-release RELEASE=release-2.17
```

**Note:** This target is automatically called by `verify-release` and `scan-release`.

#### `verify-release`
Set up a release and verify all its images (combines `setup-release` + `verify-images`).

**Usage:**
```bash
make verify-release RELEASE=release-2.17
```

#### `scan-release`
Set up a release and scan it for CVEs (combines `setup-release` + `scan-cves-json-icsp`).

**Usage:**
```bash
make scan-release RELEASE=release-2.17
```

### Reporting

#### `image-report`
Generate a comprehensive report about all images.

**Usage:**
```bash
make image-report
```

#### `slack-cve-report`
Send a CVE scan summary to Slack (requires `SLACK_WEBHOOK_URL` environment variable).

**Usage:**
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
make slack-cve-report
```

#### `slack-cve-report-detailed`
Send a detailed CVE report to Slack with more verbose information.

**Usage:**
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
make slack-cve-report-detailed
```

### Composite Targets

#### `all-checks`
Run all verification checks without CVE scanning (dummy SHA check + image verification + report).

**Usage:**
```bash
make all-checks
```

Equivalent to running:
```bash
make check-dummy-shas
make verify-images
make image-report
```

#### `full-scan`
Run all checks including CVE scanning.

**Usage:**
```bash
make full-scan
```

Equivalent to:
```bash
make all-checks
make scan-cves
```

### Maintenance and Utilities

#### `check-tools`
Verify that all required command-line tools are installed and available.

**Usage:**
```bash
make check-tools
```

#### `install-deps`
Install Python dependencies from `requirements.txt`.

**Usage:**
```bash
make install-deps
```

#### `make-scripts-executable`
Ensure all scripts in the `scripts/` directory have executable permissions.

**Usage:**
```bash
make make-scripts-executable
```

#### `clean-reports`
Remove the reports directory and all generated reports.

**Usage:**
```bash
make clean-reports
```

## Common Workflows

### Testing a New Release

```bash
# Verify all images are pullable
make verify-release RELEASE=release-2.17

# Scan for CVEs
make scan-release RELEASE=release-2.17
```

### Pre-GA Release Testing

```bash
# Set up release
make setup-release RELEASE=release-2.18

# Check for dummy SHAs (warning only, default behavior)
make check-dummy-shas

# Verify with ICSP redirects
make verify-images-icsp

# Scan with ICSP
make scan-cves-icsp
```

### Scanning a Specific Component

```bash
# Scan just the multiclusterhub operator
make scan-cves IMAGE_KEY=multiclusterhub_operator

# Scan specific component from a release
make scan-cves RELEASE=release-2.17 IMAGE_KEY=cluster_curator_controller
```

### Multi-Architecture Verification

```bash
# Verify all supported architectures
make verify-images-amd64
make verify-images-arm64
make verify-images-ppc64le
make verify-images-s390x
```

### Custom CVE Severity Scanning

```bash
# Scan for all severity levels
make scan-cves TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM,LOW

# Only critical vulnerabilities
make scan-cves TRIVY_SEVERITY=CRITICAL
```

### CI/CD Integration

```bash
# Full verification pipeline
make check-tools
make install-deps
make all-checks
make scan-cves-json > cve-report.json

# Send results to Slack
export SLACK_WEBHOOK_URL="$WEBHOOK_URL"
make slack-cve-report
```

## Environment Variable Examples

```bash
# Custom directories
EXTRAS_DIR=my-extras REPORTS_DIR=my-reports make verify-images

# Custom Trivy settings
TRIVY_TIMEOUT=30m TRIVY_SEVERITY=CRITICAL make scan-cves

# Combining multiple variables
RELEASE=release-2.17 IMAGE_KEY=multiclusterhub_operator TRIVY_SEVERITY=HIGH,CRITICAL make scan-cves
```

## Script Files

All Makefile targets invoke Python scripts located in the `scripts/` directory:

- `list_images.py` - List images from manifest files
- `check_dummy_shas.py` - Validate SHA digests
- `verify_images.py` - Verify image pullability
- `scan_cves.py` - Scan images for CVEs
- `image_report.py` - Generate image reports
- `slack_cve_report.py` - Send reports to Slack
- `setup_release.sh` - Set up release branches

## Tips

1. Use `make help` to see a quick reference of all targets
2. Run `make check-tools` before starting work to ensure all dependencies are available
3. **Important**: All scripts require the `python3` command (not just `python`). Ensure `python3` is available in your PATH
4. Use `RELEASE=` parameter for quick release switching without manual branch checkouts
5. Combine `IMAGE_KEY=` with any scan target to focus on a specific component
6. Use `verify-images-podman` if you don't have skopeo installed
7. Use `list-images-full` when you need to copy complete SHA-256 digests
8. Clean up old reports periodically with `make clean-reports`
