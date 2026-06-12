# CVE Trend Dashboard - Mockup

## CLI Output Example

```
$ make cve-trends RELEASE=release-2.17

╔══════════════════════════════════════════════════════════════════════╗
║  CVE Trend Report - release-2.17                                     ║
║  Period: Last 8 weeks (2026-04-16 to 2026-06-11)                     ║
╚══════════════════════════════════════════════════════════════════════╝

📈 Trend Summary
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┳━━━━━━━━━┓
┃ Week       ┃ CRITICAL ┃ HIGH ┃ Change ┃ Status  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━╇━━━━━━━━━┩
│ 2026-06-06 │    12    │  47  │  +3↑   │ 🔴 Worse │
│ 2026-05-30 │     9    │  44  │  -1↓   │ 🟢 Better│
│ 2026-05-23 │    10    │  45  │  +5↑   │ 🔴 Worse │
│ 2026-05-16 │     5    │  40  │  -2↓   │ 🟢 Better│
│ 2026-05-09 │     7    │  42  │  +1↑   │ 🔴 Worse │
│ 2026-05-02 │     6    │  41  │   0→   │ 🟡 Same  │
│ 2026-04-25 │     6    │  41  │  -3↓   │ 🟢 Better│
│ 2026-04-18 │     9    │  44  │   -    │    -    │
└────────────┴──────────┴──────┴────────┴─────────┘

🔍 New CVEs This Week (3)
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ CVE ID          ┃ Severity ┃ Component            ┃ Fixable    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ CVE-2026-12345  │ CRITICAL │ console              │ ✓ Yes      │
│ CVE-2026-12346  │ CRITICAL │ multiclusterhub_op   │ ✗ No       │
│ CVE-2026-12347  │ CRITICAL │ search_api           │ ✓ Yes      │
└─────────────────┴──────────┴──────────────────────┴────────────┘

✅ Fixed CVEs (Resolved since last scan)
  • CVE-2026-11111 in cluster_lifecycle (HIGH)
  • CVE-2026-11112 in governance_controller (MEDIUM)

🏆 Top Offenders (by CVE count over period)
  1. console: 127 total CVEs (23 CRITICAL, 54 HIGH)
  2. multiclusterhub_operator: 89 total CVEs (18 CRITICAL, 41 HIGH)
  3. search_api: 67 total CVEs (12 CRITICAL, 35 HIGH)

📊 Stats
  • Total scans: 8
  • Avg CRITICAL per week: 8.0
  • Avg HIGH per week: 43.0
  • Trending: 🔴 Worsening (12 vs 9 four weeks ago)
  • JIRA tickets created: 15 (auto-filed via /cve-to-jira)
```

## HTML Report Preview

```html
<!DOCTYPE html>
<html>
<head>
    <title>ACM CVE Trends - release-2.17</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>🔒 ACM CVE Trend Dashboard</h1>
    <p class="meta">Release: <strong>release-2.17</strong> | Updated: 2026-06-11 09:00 UTC</p>
    
    <!-- Line chart showing CVE trends over time -->
    <canvas id="trendChart"></canvas>
    
    <!-- Stacked bar chart: new vs fixed CVEs per week -->
    <canvas id="deltaChart"></canvas>
    
    <!-- Table: component breakdown -->
    <table class="component-table">
        <thead>
            <tr>
                <th>Component</th>
                <th>Current CRITICAL</th>
                <th>Current HIGH</th>
                <th>4-Week Trend</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <tr class="status-red">
                <td>console</td>
                <td>23</td>
                <td>54</td>
                <td>📈 +8 (worse)</td>
                <td><a href="jira-filter?component=console">View JIRAs</a></td>
            </tr>
            <!-- ... more rows ... -->
        </tbody>
    </table>
    
    <!-- Timeline: key events -->
    <div class="timeline">
        <h2>📅 Timeline</h2>
        <ul>
            <li><span class="date">2026-06-06</span> - CRITICAL spike (+3) in console and search_api</li>
            <li><span class="date">2026-05-23</span> - Major upstream golang vulnerability affects 15 components</li>
            <li><span class="date">2026-05-02</span> - Mirrored images to stage.redhat.io for faster scans</li>
        </ul>
    </div>
</body>
</html>
```

## Data Storage Structure

```json
{
  "release": "release-2.17",
  "scans": [
    {
      "timestamp": "2026-06-06T09:00:00Z",
      "scan_id": "12345",
      "github_run_id": "9876543210",
      "summary": {
        "total_images": 45,
        "total_cves": 234,
        "by_severity": {
          "CRITICAL": 12,
          "HIGH": 47,
          "MEDIUM": 98,
          "LOW": 77
        }
      },
      "new_cves": [
        {
          "cve_id": "CVE-2026-12345",
          "severity": "CRITICAL",
          "component": "console",
          "fixable": true,
          "jira_ticket": "ACM-98765"
        }
      ],
      "fixed_cves": ["CVE-2026-11111", "CVE-2026-11112"],
      "component_breakdown": {
        "console": {
          "CRITICAL": 5,
          "HIGH": 12,
          "total": 34
        },
        "multiclusterhub_operator": {
          "CRITICAL": 3,
          "HIGH": 8,
          "total": 21
        }
      }
    }
  ],
  "metadata": {
    "last_updated": "2026-06-11T10:15:00Z",
    "scan_frequency": "weekly",
    "retention_weeks": 26
  }
}
```

## Slack Integration Output

```
🔒 *Weekly CVE Scan - release-2.17*
📅 Week of June 6, 2026

*Summary*
• CRITICAL: 12 (+3 from last week) 🔴
• HIGH: 47 (+3 from last week) 🔴
• Total CVEs: 234

*New This Week*
🆕 3 new CRITICAL CVEs detected:
  • CVE-2026-12345 in console (fixable) → <JIRA link>
  • CVE-2026-12346 in multiclusterhub_op (not fixable) → <JIRA link>
  • CVE-2026-12347 in search_api (fixable) → <JIRA link>

*Resolved*
✅ 2 CVEs fixed since last scan

*Trend*
📈 Trending worse (+6 total over past 4 weeks)

<View full report> | <Component breakdown> | <GitHub Actions run>

/thread (8 replies) ↓
```

## Implementation Files

**New Scripts:**
- `scripts/cve_trends.py` - Main trend analysis engine
- `scripts/generate_trend_report.py` - HTML/markdown report generator
- `scripts/store_scan_results.py` - Persist scan data to JSON history file
- `scripts/slack_trend_summary.py` - Enhanced Slack reporting with trends

**Data Storage:**
- `reports/trends/release-2.17-history.json` - Rolling window of scan results
- `reports/trends/release-2.17-latest.html` - Auto-generated HTML dashboard

**Makefile Targets:**
```makefile
cve-trends:          # Generate trend report from stored history
cve-trends-html:     # Generate HTML dashboard
cve-trends-slack:    # Send trend summary to Slack
store-scan-result:   # Save current scan to history (auto-called by scan-cves-json)
```

**Workflow Integration:**
Modify `.github/workflows/weekly-cve-scan.yml`:
```yaml
- name: Store scan results for trending
  run: make store-scan-result

- name: Generate trend report
  run: make cve-trends-html

- name: Upload trend report
  uses: actions/upload-artifact@v4
  with:
    name: trend-dashboard-${{ env.RELEASE_BRANCH }}
    path: reports/trends/*.html
```

## Key Features

1. **Automatic Detection:** New vs fixed CVEs calculated by diff against previous scan
2. **Multi-Release Support:** Separate trend tracking per release branch
3. **Retention:** 26 weeks of history (configurable)
4. **Zero Config:** Automatically stores data during weekly scans
5. **Human + Machine:** CLI for devs, HTML for management, JSON for automation
6. **Slack Threading:** Weekly updates posted to same thread for continuity
7. **JIRA Integration:** Links to auto-created tickets via existing `/cve-to-jira` skill
