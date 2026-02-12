#!/usr/bin/env python3
"""Send CVE scan results to Slack webhook"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
import urllib.request
import urllib.error

from rich.console import Console

console = Console()


def load_previous_scan_results(previous_reports_dir, version):
    """Load previous scan results for comparison

    Args:
        previous_reports_dir: Directory containing previous scan JSON files
        version: ACM version to match

    Returns:
        Dict mapping image_key to CVE counts, or None if no previous results
    """
    previous_path = Path(previous_reports_dir)
    if not previous_path.exists():
        return None

    previous_results = {}

    # Check for organized structure first (reports/version/json/)
    version_path = previous_path / version / 'json'
    if version_path.exists():
        search_path = version_path
    else:
        # Fall back to version directory or flat structure
        version_path = previous_path / version
        if version_path.exists():
            search_path = version_path
        else:
            search_path = previous_path

    # Look for JSON reports matching the pattern
    json_reports = sorted(search_path.glob(f"{version}_*_trivy.json"))

    if not json_reports:
        return None

    for json_file in json_reports:
        # Extract image_key from filename: {version}_{image_key}_trivy.json
        filename = json_file.name
        if filename.startswith(f"{version}_") and filename.endswith("_trivy.json"):
            image_key = filename.replace(f"{version}_", "").replace("_trivy.json", "")

            cve_data = parse_trivy_json(json_file)
            if cve_data:
                previous_results[image_key] = cve_data

    return previous_results if previous_results else None


def compare_scan_results(current_results, previous_results):
    """Compare current scan results with previous scan

    Args:
        current_results: List of current scan results
        previous_results: Dict mapping image_key to previous CVE counts

    Returns:
        Dict with comparison data:
        {
            'new_components': [list of components not in previous scan],
            'removed_components': [list of components in previous but not current],
            'improved': [list of components with fewer CVEs],
            'worsened': [list of components with more CVEs],
            'unchanged': [list of components with same CVE count],
            'net_change': {'critical': delta, 'high': delta, 'total': delta}
        }
    """
    if not previous_results:
        return None

    comparison = {
        'new_components': [],
        'removed_components': [],
        'improved': [],
        'worsened': [],
        'unchanged': [],
        'net_change': {'critical': 0, 'high': 0, 'total': 0}
    }

    # Build dict of current results
    current_dict = {}
    for result in current_results:
        if result['status'] == 'success' and result.get('cve_count'):
            current_dict[result['image']] = result['cve_count']

    # Calculate totals
    current_total_critical = sum(cve.get('critical', 0) for cve in current_dict.values())
    current_total_high = sum(cve.get('high', 0) for cve in current_dict.values())
    current_total = sum(cve.get('total', 0) for cve in current_dict.values())

    previous_total_critical = sum(cve.get('critical', 0) for cve in previous_results.values())
    previous_total_high = sum(cve.get('high', 0) for cve in previous_results.values())
    previous_total = sum(cve.get('total', 0) for cve in previous_results.values())

    comparison['net_change'] = {
        'critical': current_total_critical - previous_total_critical,
        'high': current_total_high - previous_total_high,
        'total': current_total - previous_total
    }

    # Find new components
    for image_key in current_dict.keys():
        if image_key not in previous_results:
            comparison['new_components'].append(image_key)

    # Find removed components
    for image_key in previous_results.keys():
        if image_key not in current_dict:
            comparison['removed_components'].append(image_key)

    # Compare existing components
    for image_key, current_cve in current_dict.items():
        if image_key in previous_results:
            prev_cve = previous_results[image_key]

            current_count = current_cve.get('critical', 0) + current_cve.get('high', 0)
            prev_count = prev_cve.get('critical', 0) + prev_cve.get('high', 0)

            if current_count < prev_count:
                comparison['improved'].append({
                    'image': image_key,
                    'previous': prev_count,
                    'current': current_count,
                    'delta': current_count - prev_count,
                    'prev_critical': prev_cve.get('critical', 0),
                    'curr_critical': current_cve.get('critical', 0)
                })
            elif current_count > prev_count:
                comparison['worsened'].append({
                    'image': image_key,
                    'previous': prev_count,
                    'current': current_count,
                    'delta': current_count - prev_count,
                    'prev_critical': prev_cve.get('critical', 0),
                    'curr_critical': current_cve.get('critical', 0)
                })
            else:
                comparison['unchanged'].append(image_key)

    return comparison


def parse_cve_summary(summary_file):
    """Parse the CVE summary file to extract results"""
    results = []
    total_scanned = 0
    total_failed = 0
    
    with open(summary_file, 'r') as f:
        for line in f:
            if line.startswith('✓'):
                parts = line.split(':')
                if len(parts) >= 2:
                    image_key = parts[0].replace('✓', '').strip()
                    # Try to find CVE count in the file
                    results.append({
                        'image': image_key,
                        'status': 'success',
                        'cves': 0  # We'll parse this from JSON reports
                    })
                    total_scanned += 1
            elif line.startswith('✗'):
                total_failed += 1
    
    return results, total_scanned, total_failed


def parse_trivy_json(json_file):
    """Parse Trivy JSON output to count CVEs by severity"""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        critical = 0
        high = 0
        medium = 0
        low = 0
        critical_cves = []
        high_cves = []
        has_fix = 0
        no_fix = 0

        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', '').upper()
                cve_id = vuln.get('VulnerabilityID', '')
                title = vuln.get('Title', '')
                fixed_version = vuln.get('FixedVersion', '')
                pkg_name = vuln.get('PkgName', '')

                # Track fixability
                if fixed_version:
                    has_fix += 1
                else:
                    no_fix += 1

                if severity == 'CRITICAL':
                    critical += 1
                    critical_cves.append({
                        'id': cve_id,
                        'severity': severity,
                        'title': title[:80],  # Truncate long titles
                        'fixed_version': fixed_version,
                        'pkg_name': pkg_name
                    })
                elif severity == 'HIGH':
                    high += 1
                    high_cves.append({
                        'id': cve_id,
                        'severity': severity,
                        'title': title[:80],
                        'fixed_version': fixed_version,
                        'pkg_name': pkg_name
                    })
                elif severity == 'MEDIUM':
                    medium += 1
                elif severity == 'LOW':
                    low += 1

        # Prioritize CRITICAL, then HIGH
        details = critical_cves + high_cves[:10]  # All critical + top 10 high

        return {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'total': critical + high + medium + low,
            'details': details,
            'has_fix': has_fix,
            'no_fix': no_fix
        }
    except:
        return None


def create_slack_message(version, results, format_type='summary', image_details=None, threaded=False, comparison=None):
    """Create Slack message

    Args:
        version: ACM version
        results: List of scan results
        format_type: 'summary' or 'detailed'
        image_details: Optional dict mapping image_key to full image reference
        threaded: If True, return main message and thread replies separately
        comparison: Optional comparison data from compare_scan_results()

    Returns:
        If threaded=True: {'main': {...}, 'threads': [...]}
        If threaded=False: {'blocks': [...]}
    """

    if format_type == 'summary':
        # Calculate totals
        total_scanned = len([r for r in results if r['status'] == 'success'])
        total_failed = len([r for r in results if r['status'] == 'failed'])
        total_cves = sum(r.get('cve_count', {}).get('total', 0) for r in results if r.get('cve_count'))
        total_critical = sum(r.get('cve_count', {}).get('critical', 0) for r in results if r.get('cve_count'))
        total_high = sum(r.get('cve_count', {}).get('high', 0) for r in results if r.get('cve_count'))

        # Sort ALL results alphabetically (including failed scans)
        all_components = sorted(results, key=lambda x: x['image'])

        # Get top impacted (critical CVEs only, sorted by critical count, limit to top 10)
        top_impacted = sorted(
            [r for r in results if r.get('cve_count') and r['cve_count'].get('critical', 0) > 0],
            key=lambda x: (x['cve_count'].get('critical', 0), x['cve_count'].get('high', 0)),
            reverse=True
        )[:10]  # Limit to top 10

        # Determine severity level for header
        severity_emoji = "🚨" if total_critical > 10 else "⚠️" if total_critical > 0 else "✅"

        # Use Block Kit for header and summary, plain text for components
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} CVE ALERT - ACM {version} Scan Results",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"📅 *Scan Time:* {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                           f"📦 *Images Scanned:* {total_scanned} successful, {total_failed} failed"
                           + (f" (⚠️ {int(total_failed/(total_scanned+total_failed)*100)}% failure rate)" if total_failed > 10 else "")
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"🛑 *Total Vulnerabilities:* {total_cves}\n"
                           f"   • {total_critical} CRITICAL\n"
                           f"   • {total_high} HIGH"
                }
            },
            {
                "type": "divider"
            }
        ]

        # Add CVE trends section if comparison data is available
        if comparison:
            net_change = comparison['net_change']
            critical_delta = net_change['critical']
            high_delta = net_change['high']
            total_delta = net_change['total']

            # Determine trend emoji and color
            if critical_delta < 0:
                trend_emoji = "📉"
                trend_color = "green"
            elif critical_delta > 0:
                trend_emoji = "📈"
                trend_color = "red"
            else:
                trend_emoji = "➡️"
                trend_color = "yellow"

            # Build trend summary
            trend_text = f"{trend_emoji} *CVE Trends (vs. previous scan):*\n"

            if total_delta == 0:
                trend_text += "   • No change in total CVE count\n"
            else:
                sign = "+" if total_delta > 0 else ""
                trend_text += f"   • Total CVEs: {sign}{total_delta}\n"

            if critical_delta != 0:
                sign = "+" if critical_delta > 0 else ""
                trend_text += f"   • CRITICAL: {sign}{critical_delta}\n"

            if high_delta != 0:
                sign = "+" if high_delta > 0 else ""
                trend_text += f"   • HIGH: {sign}{high_delta}\n"

            # Add component changes
            improved_count = len(comparison['improved'])
            worsened_count = len(comparison['worsened'])
            new_count = len(comparison['new_components'])
            removed_count = len(comparison['removed_components'])

            if improved_count > 0:
                trend_text += f"   • ✅ {improved_count} component(s) improved\n"
            if worsened_count > 0:
                trend_text += f"   • ⚠️ {worsened_count} component(s) worsened\n"
            if new_count > 0:
                trend_text += f"   • 🆕 {new_count} new component(s)\n"
            if removed_count > 0:
                trend_text += f"   • ➖ {removed_count} component(s) removed\n"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": trend_text
                }
            })
            blocks.append({"type": "divider"})

        # Build Top Impacted Components section (CRITICAL CVEs only)
        plain_text = ""
        if top_impacted:
            total_with_critical = len([r for r in results if r.get('cve_count') and r['cve_count'].get('critical', 0) > 0])
            if total_with_critical > 10:
                plain_text = f"🔥 *Top 10 Impacted Components ({total_with_critical} total with CRITICAL CVEs):*\n"
            else:
                plain_text = f"🔥 *Top Impacted Components ({len(top_impacted)} with CRITICAL CVEs):*\n"

            for img in top_impacted:
                cve = img['cve_count']
                critical_count = cve.get('critical', 0)
                high_count = cve.get('high', 0)
                image_name = img['image']

                # Get critical CVEs for this specific image
                cve_list = []
                if cve.get('details'):
                    critical_cves_data = [d for d in cve['details'] if d.get('severity') == 'CRITICAL']
                    cve_list = [d['id'] for d in critical_cves_data]

                # Full image reference
                image_ref = ""
                if image_details and image_name in image_details:
                    image_ref = image_details[image_name]

                # Build component section text
                plain_text += f"\n🔴 *{image_name}*\n"
                plain_text += f"{critical_count} CRIT, {high_count} HIGH\n"
                plain_text += f"`{image_ref}`\n"

                # Add CVE links (simple format - up to 5 CVEs)
                if cve_list:
                    for cve_detail in cve.get('details', [])[:5]:
                        if cve_detail.get('severity') == 'CRITICAL':
                            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_detail['id']}"
                            cve_id = cve_detail['id']
                            plain_text += f"<{nvd_link}|{cve_id}> "
                    plain_text += "\n"

                # Remediation based on fix availability
                has_fix = cve.get('has_fix', 0)
                no_fix = cve.get('no_fix', 0)
                total = has_fix + no_fix

                if total == 0:
                    remediation = "Monitor for updates"
                elif has_fix == total:
                    remediation = f"✅ All {total} CVEs fixable"
                elif has_fix > 0:
                    remediation = f"⚠️ {has_fix}/{total} CVEs fixable"
                else:
                    remediation = f"❌ No fixes available"

                plain_text += f"{remediation}\n"

                # Add separator between components
                plain_text += "───────────────────\n"

        # Build All Components section (compact)
        all_components_text = f"\n📋 *All Components ({len(all_components)} total, alphabetically):*\n"
        for comp in all_components:
            image_name = comp['image']
            status = comp['status']

            if status == 'success' and comp.get('cve_count'):
                cve = comp['cve_count']
                critical_count = cve.get('critical', 0)
                high_count = cve.get('high', 0)
                total_count = cve.get('total', 0)

                # Emoji based on severity
                emoji = "🔴" if critical_count > 0 else "🟠" if high_count > 0 else "🟢"
                all_components_text += f"{emoji} {image_name}: {total_count} CVEs ({critical_count} CRIT, {high_count} HIGH)\n"
            elif status == 'failed':
                all_components_text += f"❌ {image_name}: SCAN FAILED\n"
            else:
                # Check if it has a placeholder SHA
                if image_details and image_name in image_details:
                    image_ref = image_details[image_name]
                    if 'sha256:0000000000' in image_ref:
                        all_components_text += f"⚪ {image_name}: PLACEHOLDER SHA\n"
                    else:
                        all_components_text += f"❓ {image_name}: UNKNOWN STATUS\n"
                else:
                    all_components_text += f"❓ {image_name}: UNKNOWN STATUS\n"

        # Store component sections for threading
        top_impacted_block = None
        all_components_block = None
        comparison_block = None

        if threaded:
            # In threaded mode, save component sections for thread replies
            # Main message gets ONLY summary, details go in thread
            if plain_text:
                top_impacted_block = {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": plain_text
                    }
                }

            all_components_block = {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": all_components_text
                }
            }

            # Add detailed component changes if comparison data exists
            if comparison:
                comparison_details = ""

                # Worsened components (show first - highest priority)
                if comparison['worsened']:
                    comparison_details += "⚠️ *Worsened Components:*\n"
                    # Sort by delta (worst first)
                    worsened_sorted = sorted(comparison['worsened'], key=lambda x: x['delta'], reverse=True)
                    for comp in worsened_sorted[:10]:  # Limit to top 10
                        crit_change = comp['curr_critical'] - comp['prev_critical']
                        crit_str = f" ({crit_change:+d} CRIT)" if crit_change != 0 else ""
                        comparison_details += f"  • {comp['image']}: {comp['previous']} → {comp['current']} ({comp['delta']:+d}{crit_str})\n"
                    if len(worsened_sorted) > 10:
                        comparison_details += f"  ... and {len(worsened_sorted) - 10} more\n"
                    comparison_details += "\n"

                # Improved components
                if comparison['improved']:
                    comparison_details += "✅ *Improved Components:*\n"
                    # Sort by improvement (best first)
                    improved_sorted = sorted(comparison['improved'], key=lambda x: x['delta'])
                    for comp in improved_sorted[:10]:  # Limit to top 10
                        crit_change = comp['curr_critical'] - comp['prev_critical']
                        crit_str = f" ({crit_change:+d} CRIT)" if crit_change != 0 else ""
                        comparison_details += f"  • {comp['image']}: {comp['previous']} → {comp['current']} ({comp['delta']:+d}{crit_str})\n"
                    if len(improved_sorted) > 10:
                        comparison_details += f"  ... and {len(improved_sorted) - 10} more\n"
                    comparison_details += "\n"

                # New components
                if comparison['new_components']:
                    comparison_details += "🆕 *New Components:*\n"
                    for comp in comparison['new_components'][:10]:
                        comparison_details += f"  • {comp}\n"
                    if len(comparison['new_components']) > 10:
                        comparison_details += f"  ... and {len(comparison['new_components']) - 10} more\n"
                    comparison_details += "\n"

                # Removed components
                if comparison['removed_components']:
                    comparison_details += "➖ *Removed Components:*\n"
                    for comp in comparison['removed_components'][:10]:
                        comparison_details += f"  • {comp}\n"
                    if len(comparison['removed_components']) > 10:
                        comparison_details += f"  ... and {len(comparison['removed_components']) - 10} more\n"

                if comparison_details:
                    comparison_block = {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": comparison_details
                        }
                    }

        # In webhook mode, DON'T add component details to main message
        # Keep it concise for multi-release scanning

        # Add divider before risk assessment
        blocks.append({"type": "divider"})

        # Risk assessment
        if total_critical > 10:
            risk_level = "HIGH"
            risk_emoji = "🔴"
        elif total_critical > 0:
            risk_level = "MEDIUM"
            risk_emoji = "🟠"
        else:
            risk_level = "LOW"
            risk_emoji = "🟢"

        risk_text = f"{risk_emoji} *Risk Assessment:*\n"
        risk_text += f"   • Production release risk: *{risk_level}*\n"

        if total_critical > 0:
            risk_text += f"   • {total_critical} CRITICAL vulnerabilities present in runtime components\n"

        if total_failed > 20:
            failure_pct = int(total_failed/(total_scanned+total_failed)*100)
            risk_text += f"   • Scan reliability degraded ({failure_pct}% failure rate)\n"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": risk_text
            }
        })

        # Action items
        action_text = "🎯 *Recommended Actions:*\n"

        if total_failed > 10:
            action_text += f"1. Investigate {total_failed} scan failures (registry/auth/connectivity?)\n"

        if total_critical > 5:
            action_text += "2. Block release promotion until CRITICAL CVEs are reviewed\n"

        if top_impacted and len(top_impacted) > 0:
            top_image = top_impacted[0]['image']
            action_text += f"3. Triage `{top_image}` first (highest concentration of CRIT)\n"

        action_text += "4. Check detailed reports in workflow artifacts\n"

        if total_high > 50:
            action_text += f"5. Verify base image updates for affected components\n"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": action_text
            }
        })

        # Footer with owner/follow-up
        if total_critical > 0 or total_failed > 10:
            blocks.append({"type": "divider"})
            footer_text = "🧪 *Suggested Follow-up:*\n"
            footer_text += "• Re-run full scan to confirm results\n"
            footer_text += "• Compare image digests between scans\n"
            if total_critical > 0:
                footer_text += "• Check for upstream base image CVE disclosures\n"

            footer_text += "\n_Owner: @security-team_"

            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": footer_text
                }]
            })

        # Return based on mode
        if threaded:
            # Main message: summary, risk, actions
            # Thread messages: component details
            thread_messages = []
            if comparison_block:
                thread_messages.append({"blocks": [comparison_block]})
            if top_impacted_block:
                thread_messages.append({"blocks": [top_impacted_block]})
            if all_components_block:
                thread_messages.append({"blocks": [all_components_block]})

            return {
                'main': {'blocks': blocks},
                'threads': thread_messages
            }
        else:
            # Webhook mode: everything in one message
            return {"blocks": blocks}
    
    elif format_type == 'detailed':
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 Detailed CVE Report - ACM {version}",
                    "emoji": True
                }
            }
        ]
        
        for result in results:
            if result['status'] != 'success' or not result.get('cve_count'):
                continue
            
            cve = result['cve_count']
            if cve['total'] == 0:
                continue
            
            emoji = "🔴" if cve.get('critical', 0) > 0 else "🟠"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{result['image']}* - {cve['total']} CVEs\n"
                           f"• {cve.get('critical', 0)} CRITICAL, {cve.get('high', 0)} HIGH, "
                           f"{cve.get('medium', 0)} MEDIUM, {cve.get('low', 0)} LOW"
                }
            })
            
            if cve.get('details'):
                cve_list = "\n".join([
                    f"  - {d['id']} ({d['severity']}): {d['title']}"
                    for d in cve['details'][:5]
                ])
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```{cve_list}```"
                    }
                })
        
        return {"blocks": blocks}


def send_to_slack(webhook_url, message):
    """Send message to Slack webhook"""
    try:
        # Add custom username and icon to match bot appearance
        message['username'] = 'ACM Konflux Support'
        message['icon_emoji'] = ':robot_face:'

        data = json.dumps(message).encode('utf-8')
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status == 200:
                return True
            else:
                console.print(f"[red]Slack API returned status {response.status}[/red]")
                return False
    except urllib.error.URLError as e:
        console.print(f"[red]Failed to send to Slack: {e}[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def send_to_slack_threaded(bot_token, channel, main_message, thread_messages):
    """Send main message and thread replies using Slack API

    Args:
        bot_token: Slack bot OAuth token (xoxb-...)
        channel: Channel ID or name (e.g., 'C1234567890' or '#channel-name')
        main_message: Main message blocks
        thread_messages: List of message texts/blocks to post as thread replies

    Returns:
        bool: True if successful
    """
    try:
        # Post main message
        main_payload = {
            'channel': channel,
            'blocks': main_message['blocks']
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {bot_token}'
        }

        data = json.dumps(main_payload).encode('utf-8')
        req = urllib.request.Request(
            'https://slack.com/api/chat.postMessage',
            data=data,
            headers=headers
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))

            if not result.get('ok'):
                console.print(f"[red]Slack API error: {result.get('error')}[/red]")
                return False

            # Get parent message timestamp for threading
            parent_ts = result.get('ts')
            console.print(f"[green]✓ Main message posted (ts: {parent_ts})[/green]")

        # Post thread replies
        for i, thread_msg in enumerate(thread_messages, 1):
            thread_payload = {
                'channel': channel,
                'thread_ts': parent_ts,
                'text': thread_msg if isinstance(thread_msg, str) else thread_msg.get('text', ''),
            }

            # Add blocks if present
            if isinstance(thread_msg, dict) and 'blocks' in thread_msg:
                thread_payload['blocks'] = thread_msg['blocks']

            data = json.dumps(thread_payload).encode('utf-8')
            req = urllib.request.Request(
                'https://slack.com/api/chat.postMessage',
                data=data,
                headers=headers
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))

                if not result.get('ok'):
                    console.print(f"[red]Thread reply {i} error: {result.get('error')}[/red]")
                    return False

                console.print(f"[green]✓ Thread reply {i} posted[/green]")

        return True

    except urllib.error.URLError as e:
        console.print(f"[red]Failed to send to Slack: {e}[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def main():
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    bot_token = os.getenv('SLACK_BOT_TOKEN')
    channel = os.getenv('SLACK_CHANNEL')
    reports_dir = os.getenv('REPORTS_DIR', 'reports')
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')
    format_type = os.getenv('SLACK_FORMAT', 'summary')  # summary or detailed
    use_threading = os.getenv('SLACK_USE_THREADING', 'true').lower() == 'true'
    previous_reports_dir = os.getenv('PREVIOUS_REPORTS_DIR', None)  # Optional: path to previous scan reports

    # Determine mode: threaded (bot token) or webhook
    if bot_token and channel and use_threading:
        console.print(f"[blue]Using threaded mode with bot token[/blue]")
        use_threaded_mode = True
    elif webhook_url:
        console.print(f"[blue]Using webhook mode[/blue]")
        use_threaded_mode = False
    else:
        console.print("[red]Error: Either SLACK_BOT_TOKEN+SLACK_CHANNEL or SLACK_WEBHOOK_URL required[/red]")
        console.print("Webhook: export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'")
        console.print("Threaded: export SLACK_BOT_TOKEN='xoxb-...' SLACK_CHANNEL='#channel-name'")
        sys.exit(1)
    
    # Find version from extras files
    extras_path = Path(extras_dir)
    json_files = sorted(extras_path.glob('*.json'))
    if not json_files:
        console.print(f"[red]No JSON files found in {extras_dir}[/red]")
        sys.exit(1)
    
    version = json_files[0].stem  # e.g., "2.17.0"
    
    # Parse results
    console.print(f"[blue]Generating Slack report for ACM {version}...[/blue]")
    
    results = []
    image_details = {}  # Map image_key to full image reference
    reports_path = Path(reports_dir)

    # Check for organized structure (reports/version/json/ or reports/version/text/)
    version_path = reports_path / version
    if version_path.exists():
        reports_path = version_path
        console.print(f"[blue]Using organized report structure: {version_path}[/blue]")

    # Load image list
    with open(json_files[0], 'r') as f:
        images = json.load(f)

    for img in images:
        image_key = img.get('image-key', 'unknown')

        # Build full image reference
        image_remote = img.get('image-remote', '')
        image_name = img.get('image-name', '')
        image_digest = img.get('image-digest', '')
        if image_remote and image_name and image_digest:
            full_ref = f"{image_remote}/{image_name}@{image_digest}"
            image_details[image_key] = full_ref

        # Look for JSON scan report in organized structure or flat structure
        json_report = reports_path / 'json' / f"{version}_{image_key}_trivy.json"
        if not json_report.exists():
            json_report = reports_path / f"{version}_{image_key}_trivy.json"

        txt_report = reports_path / 'text' / f"{version}_{image_key}_trivy.txt"
        if not txt_report.exists():
            txt_report = reports_path / f"{version}_{image_key}_trivy.txt"
        
        if json_report.exists():
            cve_count = parse_trivy_json(json_report)
            if cve_count:
                results.append({
                    'image': image_key,
                    'status': 'success',
                    'cve_count': cve_count
                })
            else:
                # JSON parse failed, treat as failed
                results.append({
                    'image': image_key,
                    'status': 'failed'
                })
        elif txt_report.exists():
            # Parse text report (less reliable)
            results.append({
                'image': image_key,
                'status': 'success',
                'cve_count': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            })
        else:
            results.append({
                'image': image_key,
                'status': 'failed'
            })

    # Load previous scan results for comparison (if available)
    comparison = None
    if previous_reports_dir:
        console.print(f"[blue]Loading previous scan results from {previous_reports_dir}...[/blue]")
        previous_results = load_previous_scan_results(previous_reports_dir, version)

        if previous_results:
            console.print(f"[green]✓ Found previous scan with {len(previous_results)} components[/green]")
            comparison = compare_scan_results(results, previous_results)

            if comparison:
                net_change = comparison['net_change']
                console.print(f"[blue]CVE delta: {net_change['total']:+d} total, {net_change['critical']:+d} critical, {net_change['high']:+d} high[/blue]")
        else:
            console.print(f"[yellow]No previous scan results found for version {version}[/yellow]")

    # Create and send message
    message_data = create_slack_message(version, results, format_type, image_details, threaded=use_threaded_mode, comparison=comparison)

    console.print("[blue]Sending to Slack...[/blue]")

    if use_threaded_mode:
        # Threaded mode: main message + thread replies
        main_msg = message_data['main']
        thread_msgs = message_data.get('threads', [])

        if send_to_slack_threaded(bot_token, channel, main_msg, thread_msgs):
            console.print("[green]✓ Successfully sent threaded message to Slack![/green]")
        else:
            console.print("[red]✗ Failed to send to Slack[/red]")
            sys.exit(1)
    else:
        # Webhook mode: single message with all blocks
        if send_to_slack(webhook_url, message_data):
            console.print("[green]✓ Successfully sent to Slack![/green]")
        else:
            console.print("[red]✗ Failed to send to Slack[/red]")
            sys.exit(1)


if __name__ == '__main__':
    main()
