# Troubleshooting

Common CI/CD issues and how to diagnose them.

## Git fetch failures in bundle generation workflow

**Symptom:** The `Process triggering PR` step fails with:
```
fatal: unable to access 'https://github.com/stolostron/release/': Failed sending HTTP request
```

**Affected workflow:** `Gen Bundle Contents When Triggered` (`gen-bundle-contents-when-triggered.yaml`)

### Diagnosis steps

1. **Enable verbose HTTP logging** by adding `GIT_CURL_VERBOSE: 1` to the retry step's `env` block:
   ```yaml
   - name: Process triggering PR
     uses: nick-fields/retry@v3
     env:
       GIT_CURL_VERBOSE: 1
       # ... rest of env
   ```

2. **Re-run the failed job** and examine the verbose output. Key lines to look for:

   | Verbose output | Meaning |
   |---|---|
   | `Host github.com:443 was resolved` then nothing | DNS works, TCP/TLS failing |
   | `Connected to github.com` then `Failed sending HTTP request` | HTTP protocol issue (see HTTP/2 below) |
   | `HTTP/1.1 401 Unauthorized` | Token invalid or expired |
   | `HTTP/1.1 403 Forbidden` | Token valid but lacks repo access |
   | `HTTP/1.1 400 Bad Request` | Malformed headers (duplicate auth, oversized headers) |
   | `remote: Repository not found` | Private repo, token has no access |

3. **Remove `GIT_CURL_VERBOSE` after diagnosis** -- it can leak auth tokens in logs that GitHub Actions doesn't know to mask.

### Known issues

#### HTTP/2 framing failures (resolved 2026-08-06)

**Root cause:** `tools/run-script-from-tools-repo` configured two auth mechanisms simultaneously -- `credential.helper` and `http.extraheader` -- producing duplicate `Authorization` headers. HTTP/2 framing choked on the duplicate/oversized headers; HTTP/1.1 got `400 Bad Request`.

**Fix:** Removed `http.extraheader` setup, kept `credential.helper` only. If this recurs, check that only one auth mechanism is configured in the script.

**How we found it:** `GIT_CURL_VERBOSE=1` showed a successful TLS handshake followed by immediate `Failed sending HTTP request` on HTTP/2, and `400 Bad Request` with visible duplicate auth headers on HTTP/1.1 fallback.

#### HTTP/2 vs HTTP/1.1 fallback

The script includes an HTTP/1.1 fallback: if `git fetch` fails, it sets `git config http.version HTTP/1.1` and retries once. This handles cases where GitHub runners or network middleboxes break HTTP/2.

Outer retries are handled by `nick-fields/retry@v3` at the workflow step level -- the script itself does not retry beyond the protocol fallback.

## GitHub App token issues

**Symptom:** Workflow fails at `Generate GitHub token to read release tools repo` or `Generate GitHub token for workflow actions`.

### Diagnosis steps

1. Check that the GitHub App is still installed on the target org/repos
2. Verify `TOOLS_REPO_READER_APP_ID` and `TOOLS_REPO_READER_PRIVATE_KEY` are set in repo variables/secrets
3. Verify `WORKFLOW_BOT_APP_ID` and `WORKFLOW_BOT_PRIVATE_KEY` are set
4. Check GitHub App private key hasn't expired -- regenerate if needed

## Docker registry login failures

**Symptom:** `Authenticate to image registries` step fails.

### Diagnosis steps

1. Check credentials are current for:
   - `registry.redhat.io` (`REGISTRY_REDHAT_IO_RGY_USERNAME` / `REGISTRY_REDHAT_IO_RGY_PASSWORD`)
   - `registry.stage.redhat.io` (`REGISTRY_STAGE_REDHAT_IO_RGY_USERNAME` / `REGISTRY_STAGE_REDHAT_IO_RGY_PASSWORD`)
   - `quay.io` (`QUAY_IO_ACMD_RGY_USERNAME` / `QUAY_IO_ACMD_RGY_PASSWORD`)
2. Check [Red Hat SSO status](https://status.redhat.com/) for outages
3. Robot accounts / service accounts may need re-authorization periodically

## General CI debugging tips

- **Check GitHub status:** https://www.githubstatus.com/ -- correlate failure timestamps with platform incidents
- **Runner issues:** If failures are sporadic, they may be runner-specific (bad network egress, proxy, or firewall on a particular runner instance). Re-running usually lands on a different runner.
- **Node.js deprecation warnings** (e.g., `Node.js 20 is deprecated`) are informational -- they don't cause failures but indicate actions should be updated to newer versions.
- **Workflow SHA:** `pull_request_target` workflows resolve from the base branch at PR creation time. Changes to the workflow on `main` won't take effect until the next PR is opened (not on re-runs of existing PRs).
