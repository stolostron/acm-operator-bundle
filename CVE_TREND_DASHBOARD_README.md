# CVE Trend Dashboard - Implementation Guide

## Overview

Tracks CVE trends over time across ACM releases. Weekly scans stored in history, visualized via CLI tables and HTML dashboards.

## Quick Start

```bash
# After weekly scan runs, view trends
make cve-trends RELEASE=release-2.17

# Generate HTML dashboard
make cve-trends-html RELEASE=release-2.17
open reports/trends/release-2.17-dashboard.html
```

## Features

- **Automatic Storage**: Scan results auto-saved to `reports/trends/{release}-history.json`
- **New/Fixed Detection**: Compares each scan vs previous week, identifies delta
- **CLI Report**: Terminal tables showing 8-week trends, new CVEs, top offenders
- **HTML Dashboard**: Charts (line graph trends, stacked bar new/fixed), component breakdown
- **Slack Integration**: Trend dashboard link added to weekly Slack reports
- **26-Week Retention**: Rolling window, auto-prunes old data

## Files Created

### Scripts
- `scripts/store_scan_results.py` - Stores scan data to history file
- `scripts/cve_trends.py` - Generates CLI trend report
- `scripts/generate_trend_report.py` - Creates HTML dashboard
- `scripts/slack_cve_report.py` - Enhanced with trend dashboard link

### Data Storage
- `reports/trends/{release}-history.json` - Historical scan data
- `reports/trends/{release}-dashboard.html` - HTML dashboard

## Usage

### View CLI Trend Report

```bash
make cve-trends RELEASE=release-2.17
```

**Output:**
```
╔══════════════════════════════════════════════════════════════╗
║  CVE Trend Report - release-2.17                             ║
║  Period: Last 8 weeks (2026-04-16 to 2026-06-11)             ║
╚══════════════════════════════════════════════════════════════╝

📈 Trend Summary
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━┓
┃ Week       ┃ CRITICAL ┃ HIGH ┃ Change ┃ Status  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━┩
│ 2026-06-06 │    12    │  47  │  +3↑   │ 🔴 Worse │
│ 2026-05-30 │     9    │  44  │  -1↓   │ 🟢 Better│
...

🔍 New CVEs This Week (3)
...

🏆 Top Offenders (by CVE count over period)
  1. console: 127 total CVEs (23 CRITICAL, 54 HIGH)
  2. multiclusterhub_operator: 89 total CVEs (18 CRITICAL, 41 HIGH)
...
```

### Generate HTML Dashboard

```bash
make cve-trends-html RELEASE=release-2.17
```

Dashboard includes:
- Summary cards (CRITICAL, HIGH, Total, Week-over-week delta)
- Line chart: CVE trends over time
- Stacked bar chart: New vs fixed CVEs per week
- Component breakdown table
- New CVEs this week (top 15)
- Recent activity timeline

### Manual Storage (optional)

Normally automatic, but can manually store:

```bash
# After scan-cves-json runs
make store-scan-result RELEASE=release-2.17
```

### Custom Week Range

```bash
# Show last 12 weeks instead of default 8
python3 scripts/cve_trends.py --release release-2.17 --weeks 12
```

## Workflow Integration

Weekly CVE scan workflow (`weekly-cve-scan.yml`) now:

1. Runs `scan-cves-json-icsp` (auto-stores results via `store-scan-result`)
2. Generates HTML dashboard via `cve-trends-html`
3. Uploads dashboard as artifact `trend-dashboard-{release}`
4. Slack report includes "📈 Trend dashboard included" if available

**Artifacts uploaded:**
- `cve-reports-{release}-run-{number}` - JSON scan results
- `trend-dashboard-{release}` - HTML dashboard

## History File Structure

```json
{
  "release": "release-2.17",
  "scans": [
    {
      "timestamp": "2026-06-06T09:00:00Z",
      "github_run_id": "9876543210",
      "summary": {
        "total_cves": 234,
        "by_severity": {
          "CRITICAL": 12,
          "HIGH": 47,
          ...
        },
        "component_breakdown": {
          "console": {"CRITICAL": 5, "HIGH": 12, "total": 34},
          ...
        }
      },
      "new_cves": [
        {"cve_id": "CVE-2026-12345", "severity": "CRITICAL", "component": "console", "fixable": true}
      ],
      "fixed_cves": [
        {"cve_id": "CVE-2026-11111", "component": "cluster_lifecycle"}
      ]
    }
  ],
  "metadata": {
    "created": "2026-04-16T09:00:00Z",
    "last_updated": "2026-06-11T10:15:00Z",
    "retention_weeks": 26
  }
}
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `store-scan-result` | Store latest scan to history (auto-called by `scan-cves-json*`) |
| `cve-trends` | Show CLI trend report (requires RELEASE=) |
| `cve-trends-html` | Generate HTML dashboard (requires RELEASE=) |

## Retention Policy

- **Default**: 26 weeks (6 months)
- **Configurable**: Edit `retention_weeks` in history file metadata
- **Auto-pruning**: Runs during `store-scan-result`

## Troubleshooting

**"History file not found"**
- No scans stored yet. Run `make scan-cves-json RELEASE=release-2.17` first

**"Could not auto-detect release"**
- Provide `--release` flag: `make cve-trends RELEASE=release-2.17`

**No trend dashboard in Slack report**
- First scan won't have dashboard (needs 2+ scans for trends)
- Check `reports/trends/` directory exists and contains HTML

**Trends look wrong**
- Verify history file has multiple scans: `cat reports/trends/release-2.17-history.json | jq '.scans | length'`
- Check timestamps are sequential

## Integration with Existing Tools

**Works with:**
- `/cve-to-jira` skill - Creates JIRA tickets from scan results
- `slack_cve_report.py` - Adds trend dashboard link to weekly reports
- `weekly-cve-scan.yml` - Auto-stores and generates dashboards

**Complements:**
- `scan-cves` - Text output for terminal
- `scan-cves-json` - JSON output + history storage
- `verify-images` - Image pullability checks

## Next Steps

See `TREND_DASHBOARD_MOCKUP.md` for:
- Detailed output examples
- Slack integration preview
- Data structure reference

## Example Workflow

```bash
# Week 1: First scan (creates history)
make scan-cves-json-icsp RELEASE=release-2.17

# Week 2: Second scan (detects new/fixed CVEs)
make scan-cves-json-icsp RELEASE=release-2.17
make cve-trends RELEASE=release-2.17        # See trend report
make cve-trends-html RELEASE=release-2.17   # Generate dashboard

# View dashboard
open reports/trends/release-2.17-dashboard.html
```

## Configuration

**Environment Variables:**
- `REPORTS_DIR` - Reports directory (default: `reports`)
- `EXTRAS_DIR` - Extras directory for release detection (default: `extras`)
- `GITHUB_RUN_ID` - GitHub Actions run ID (auto-set in CI)

**Script Options:**
```bash
# Custom reports directory
make cve-trends RELEASE=release-2.17 REPORTS_DIR=custom-reports

# JSON output instead of table
python3 scripts/cve_trends.py --release release-2.17 --format json

# Custom HTML output path
python3 scripts/generate_trend_report.py \
  --release release-2.17 \
  --output /tmp/dashboard.html
```
