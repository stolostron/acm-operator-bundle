# GitHub Actions - CVE Scanning

## Weekly CVE Scan Workflow

The `weekly-cve-scan.yml` workflow automatically scans all ACM images for CVEs and posts results to Slack.

### Schedule
- **Runs:** Every Friday at 9 AM UTC (4 AM EST / 5 AM EDT)
- **Scans:** Automatically scans the 3 most recent releases (2.17, 2.16, 2.15)
- **Result:** 3 separate Slack notifications (one per release with trend data)
- **Manual Trigger:** Can be triggered manually from the Actions tab for any single release

### Required GitHub Secrets & Variables

#### Repository Variables (Settings → Secrets and variables → Actions → Variables tab)

These can be configured at the repository level and changed without modifying the workflow:

**`ACM_VERSION`** (optional)
- Default: `2.17.0`
- Description: ACM version to scan (should match your extras/*.json filename)
- Example: `2.17.0`

**`TRIVY_SEVERITY`** (optional)
- Default: `HIGH,CRITICAL`
- Description: CVE severity levels to scan for
- Example: `CRITICAL`, `HIGH,CRITICAL`, `HIGH,CRITICAL,MEDIUM`


#### Repository Secrets (Settings → Secrets and variables → Actions → Secrets tab)

You need to add these secrets to your repository:

#### 1. Slack Integration (choose one mode)

The workflow supports two Slack integration modes:

**Option A: Webhook Mode (Simple)**
- ✅ Easy setup, minimal permissions
- ✅ Good for multi-release scanning (12+ releases)
- ❌ No threading, all details in main channel

**Option B: Threaded Mode (Advanced)**
- ✅ Clean channel: summary in main, details in thread
- ✅ Supports bot token features
- ✅ Better for single-release scanning
- ❌ Requires bot app setup with additional permissions

**Choose Option A (Webhook) if you want:**
- Simple setup
- Concise summaries only
- Multi-release scanning (less channel noise)

**Choose Option B (Threaded) if you want:**
- Detailed component breakdown in threads
- CVE change details in thread replies
- Full component list without cluttering channel

---

#### Option A: `SLACK_CVE_WEBHOOK_URL` (Webhook Mode)

**To create:**
1. Go to https://api.slack.com/apps
2. Create a new app or use existing
3. Enable "Incoming Webhooks"
4. Create webhook for your desired channel
5. Copy the webhook URL (looks like: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX`)

**To add to GitHub:**
1. Go to your repo → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `SLACK_CVE_WEBHOOK_URL`
4. Value: Paste your webhook URL
5. Click "Add secret"

---

#### Option B: `SLACK_BOT_OAUTH_TOKEN` + `SLACK_CHANNEL` (Threaded Mode)

**To create bot token:**
1. Go to https://api.slack.com/apps
2. Create a new app or select existing
3. Go to "OAuth & Permissions"
4. Add bot token scopes:
   - `chat:write` - Post messages
   - `chat:write.public` - Post to public channels without joining
5. Install app to workspace
6. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

**To add to GitHub:**
1. Add `SLACK_BOT_OAUTH_TOKEN`:
   - Go to repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `SLACK_BOT_OAUTH_TOKEN`
   - Value: Paste your bot token (starts with `xoxb-`)

2. Add `SLACK_CVE_CHANNEL`:
   - Click "New repository secret"
   - Name: `SLACK_CVE_CHANNEL`
   - Value: Channel ID (starts with `C`) or channel name (e.g., `#cve-alerts`)

**Note:** If both `SLACK_CVE_WEBHOOK_URL` and `SLACK_BOT_OAUTH_TOKEN` are configured, the workflow will use threaded mode (bot token takes precedence).

#### 2. `QUAY_IO_ACMD_RGY_PASSWORD`

Your quay.io service account password for pulling images.

**To add to GitHub:**
1. Go to your repo → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `QUAY_IO_ACMD_RGY_PASSWORD`
4. Value: Paste your quay.io password for the `acmd+rgy` service account
5. Click "Add secret"

**Note:** This is the same secret used by other workflows - you only need to set it once.

### Manual Trigger

To run the scan manually:
1. Go to Actions tab
2. Click "Weekly CVE Scan" in the left sidebar
3. Click "Run workflow" button
4. (Optional) Override settings:
   - **acm_version**: Scan a specific version (e.g., `2.17.0`)
   - **severity**: Change severity filter (e.g., `CRITICAL` only)
5. Select branch and click "Run workflow"

Manual runs allow you to override the repository variables for one-time scans.

### What the workflow does

1. ✅ Checks out scripts from main branch and image data from release branch
2. ✅ Installs Python dependencies (rich library)
3. ✅ Installs Trivy (CVE scanner)
4. ✅ Installs Skopeo (image verification)
5. ✅ Sets up authentication for quay.io using podman
6. ✅ Verifies images are accessible with ICSP mirrors
7. ✅ Downloads previous scan results (for trend analysis)
8. ✅ Scans all images for HIGH and CRITICAL CVEs (JSON format)
9. ✅ Compares with previous scan to detect changes
10. ✅ Posts summary to Slack (with trends if available)
11. ✅ Uploads detailed reports as artifacts (kept for 90 days)
12. ✅ Checks if critical CVE count exceeds threshold

### CVE Change Detection & Trends

Starting from the second scan onwards, the workflow automatically compares the current scan results with the previous scan to track CVE trends:

**Trend Metrics Tracked:**
- **Net CVE change:** Total CVE count delta (e.g., +15, -8, or no change)
- **Severity deltas:** CRITICAL and HIGH CVE changes
- **Component improvements:** Components with fewer CVEs than before
- **Component regressions:** Components with more CVEs than before
- **New components:** Components added since last scan
- **Removed components:** Components removed since last scan

**Slack Notification Features:**
- **Main message:** Shows high-level trend summary (e.g., "📈 +5 CRITICAL, ⚠️ 3 components worsened")
- **Thread details (bot token mode):** Full breakdown of improved/worsened components with specific CVE deltas

**How it works:**
1. At the start of each scan, the workflow downloads artifacts from the most recent successful run
2. Previous scan results (JSON files) are extracted to `previous-reports/` directory
3. The Slack report script compares current vs. previous CVE counts per component
4. Trends are displayed in the Slack notification

**First scan behavior:**
- No previous data available, so no trends shown
- Subsequent scans will compare against this baseline

**Example Slack trend output:**
```
📉 CVE Trends (vs. previous scan):
   • Total CVEs: -12
   • CRITICAL: -3
   • HIGH: -9
   • ✅ 5 component(s) improved
   • ⚠️ 2 component(s) worsened
```

### Outputs

- **Slack message:** Posted to configured Slack channel
  - Summary with current CVE counts
  - Trend analysis (if previous scan exists)
  - Top impacted components
  - All components alphabetically
- **Artifacts:** Detailed CVE reports available in the workflow run (Reports → Artifacts)
  - Organized by version: `reports/2.17.0/`, `reports/2.16.0/`, etc.
  - JSON format in `reports/VERSION/json/` subdirectory
  - Includes summary file: `reports/VERSION/VERSION_cve_summary.txt`
- **Workflow logs:** Full scan output in GitHub Actions logs

### Report Structure

The workflow generates organized reports under the `reports/` directory:

```
reports/
├── 2.17.0/
│   ├── 2.17.0_cve_summary.txt          # Summary of all scans
│   └── json/                            # Machine-readable reports
│       ├── 2.17.0_component_trivy.json
│       └── ...
├── 2.16.0/
│   ├── 2.16.0_cve_summary.txt
│   └── json/
│       └── ...
└── 2.15.0/
    ├── 2.15.0_cve_summary.txt
    └── json/
        └── ...
```

**Local scans** (using Makefile) default to text format in `reports/VERSION/text/` unless `OUTPUT_JSON=true` is set.

### Customization

Edit `.github/workflows/weekly-cve-scan.yml` to customize:

- **Schedule:** Change the `cron` expression
- **Severity filter:** Modify `TRIVY_SEVERITY` (default: `HIGH,CRITICAL`)
- **Critical threshold:** Adjust the check in the last step
- **Artifact retention:** Change `retention-days` (default: 90)
- **Slack format:** Use `slack-cve-report-detailed` for more details

### Troubleshooting

**Workflow fails with authentication error:**
- Verify `QUAY_IO_ACMD_RGY_PASSWORD` secret is set correctly
- Check if your quay.io credentials are still valid
- Verify the service account username is `acmd+rgy`

**No Slack message received:**
- Verify `SLACK_CVE_WEBHOOK_URL` secret is correct
- For bot mode, verify both `SLACK_BOT_OAUTH_TOKEN` and `SLACK_CVE_CHANNEL` are set
- Check the webhook/channel is correct
- Look at workflow logs for error messages

**Images not found:**
- Images with placeholder SHAs (sha256:000000...) cannot be scanned
- Only 11 images currently have real SHAs
- This is expected for pre-GA releases
