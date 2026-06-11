#!/usr/bin/env python3
"""Store CVE scan results for historical trend tracking"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console

console = Console()


def load_history(history_file):
    """Load existing scan history or create new structure"""
    if not history_file.exists():
        return {
            "release": None,
            "scans": [],
            "metadata": {
                "created": datetime.utcnow().isoformat() + "Z",
                "last_updated": None,
                "scan_frequency": "weekly",
                "retention_weeks": 26,
                "max_scans": 4
            }
        }

    try:
        with open(history_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading history file: {e}[/red]")
        sys.exit(1)


def extract_scan_summary(scan_report):
    """Extract summary statistics from Grype JSON report"""
    matches = scan_report.get('matches', [])

    # Count by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'NEGLIGIBLE': 0,
        'UNKNOWN': 0
    }

    # Track unique CVEs and components
    cve_set = set()
    component_breakdown = {}
    cve_details = []

    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})

        cve_id = vuln.get('id', 'UNKNOWN')
        severity = vuln.get('severity', 'UNKNOWN').upper()
        component = artifact.get('name', 'unknown')

        # Count by severity
        if severity in severity_counts:
            severity_counts[severity] += 1

        # Track unique CVEs
        cve_set.add(cve_id)

        # Track per-component breakdown
        if component not in component_breakdown:
            component_breakdown[component] = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'total': 0
            }

        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            component_breakdown[component][severity] += 1
        component_breakdown[component]['total'] += 1

        # Store CVE details for new/fixed detection
        cve_details.append({
            'cve_id': cve_id,
            'severity': severity,
            'component': component,
            'fixed_versions': vuln.get('fix', {}).get('versions', []),
            'fixable': len(vuln.get('fix', {}).get('versions', [])) > 0
        })

    return {
        'total_cves': len(cve_set),
        'total_matches': len(matches),
        'by_severity': severity_counts,
        'component_breakdown': component_breakdown,
        'cve_details': cve_details
    }


def detect_changes(current_scan, previous_scan):
    """Detect new and fixed CVEs compared to previous scan"""
    if not previous_scan:
        return [], []

    current_cves = {
        (cve['cve_id'], cve['component'])
        for cve in current_scan.get('cve_details', [])
    }

    previous_cves = {
        (cve['cve_id'], cve['component'])
        for cve in previous_scan.get('cve_details', [])
    }

    new_cves = current_cves - previous_cves
    fixed_cves = previous_cves - current_cves

    # Get full details for new CVEs
    new_cve_details = [
        cve for cve in current_scan.get('cve_details', [])
        if (cve['cve_id'], cve['component']) in new_cves
    ]

    # Get CVE IDs for fixed CVEs
    fixed_cve_ids = [
        {'cve_id': cve_id, 'component': component}
        for cve_id, component in fixed_cves
    ]

    return new_cve_details, fixed_cve_ids


def detect_release_from_extras(extras_dir):
    """Auto-detect release version from extras directory"""
    extras_path = Path(extras_dir)
    if not extras_path.exists():
        return None

    # Look for version pattern in JSON filenames (e.g., 2.17.0.json)
    for json_file in extras_path.glob('*.json'):
        name = json_file.stem
        parts = name.split('.')
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return f"release-{parts[0]}.{parts[1]}"

    return None


def prune_old_scans(history, retention_weeks=None, max_scans=None):
    """Remove scans older than retention period or beyond max count"""
    if not history.get('scans'):
        return

    # Apply max_scans limit first (keep most recent N scans)
    if max_scans and len(history['scans']) > max_scans:
        # Sort by timestamp descending, keep newest max_scans
        history['scans'].sort(key=lambda s: s['timestamp'], reverse=True)
        history['scans'] = history['scans'][:max_scans]

    # Then apply time-based retention (if specified)
    if retention_weeks:
        cutoff = datetime.utcnow().timestamp() - (retention_weeks * 7 * 24 * 60 * 60)
        history['scans'] = [
            scan for scan in history['scans']
            if datetime.fromisoformat(scan['timestamp'].replace('Z', '')).timestamp() > cutoff
        ]


def main():
    parser = argparse.ArgumentParser(description='Store CVE scan results for trend tracking')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory (default: reports)')
    parser.add_argument('--extras-dir', default='extras',
                       help='Extras directory for release detection (default: extras)')
    parser.add_argument('--release',
                       help='Release name (e.g., release-2.17). Auto-detected if not provided')
    parser.add_argument('--scan-report',
                       help='Path to Grype JSON scan report. Defaults to latest in reports dir')
    parser.add_argument('--github-run-id',
                       help='GitHub Actions run ID for reference')

    args = parser.parse_args()

    # Detect release if not provided
    release = args.release
    if not release:
        release = detect_release_from_extras(args.extras_dir)
        if not release:
            console.print("[red]Could not auto-detect release. Use --release flag[/red]")
            sys.exit(1)

    console.print(f"[cyan]Storing scan results for {release}[/cyan]")

    # Find scan report
    scan_report_path = args.scan_report
    if not scan_report_path:
        # Look for latest Grype JSON in reports dir
        reports_path = Path(args.reports_dir)
        json_files = list(reports_path.glob('*-grype.json'))
        if not json_files:
            console.print(f"[red]No Grype JSON reports found in {args.reports_dir}[/red]")
            sys.exit(1)
        scan_report_path = max(json_files, key=lambda p: p.stat().st_mtime)

    scan_report_path = Path(scan_report_path)
    if not scan_report_path.exists():
        console.print(f"[red]Scan report not found: {scan_report_path}[/red]")
        sys.exit(1)

    console.print(f"[cyan]Loading scan report: {scan_report_path}[/cyan]")

    # Load scan report
    try:
        with open(scan_report_path, 'r') as f:
            scan_report = json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading scan report: {e}[/red]")
        sys.exit(1)

    # Extract summary
    summary = extract_scan_summary(scan_report)

    # Load or create history
    trends_dir = Path(args.reports_dir) / 'trends'
    trends_dir.mkdir(parents=True, exist_ok=True)

    history_file = trends_dir / f"{release}-history.json"
    history = load_history(history_file)

    # Set release name if new history
    if not history.get('release'):
        history['release'] = release

    # Get previous scan for comparison
    previous_scan = history['scans'][-1]['summary'] if history.get('scans') else None

    # Detect new and fixed CVEs
    new_cves, fixed_cves = detect_changes(summary, previous_scan)

    # Create scan record
    scan_record = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'scan_report_path': str(scan_report_path),
        'github_run_id': args.github_run_id or os.environ.get('GITHUB_RUN_ID'),
        'summary': {
            'total_cves': summary['total_cves'],
            'total_matches': summary['total_matches'],
            'by_severity': summary['by_severity'],
            'component_breakdown': summary['component_breakdown']
        },
        'new_cves': new_cves,
        'fixed_cves': fixed_cves
    }

    # Append to history
    history['scans'].append(scan_record)
    history['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

    # Prune old scans
    retention_weeks = history['metadata'].get('retention_weeks', 26)
    max_scans = history['metadata'].get('max_scans', 4)
    prune_old_scans(history, retention_weeks=retention_weeks, max_scans=max_scans)

    # Save history
    try:
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
        console.print(f"[green]✓ Scan results stored: {history_file}[/green]")
    except Exception as e:
        console.print(f"[red]Error saving history: {e}[/red]")
        sys.exit(1)

    # Print summary
    console.print(f"\n[bold]Scan Summary[/bold]")
    console.print(f"  Total CVEs: {summary['total_cves']}")
    console.print(f"  CRITICAL: {summary['by_severity']['CRITICAL']}")
    console.print(f"  HIGH: {summary['by_severity']['HIGH']}")

    if new_cves:
        console.print(f"\n[yellow]  New CVEs: {len(new_cves)}[/yellow]")
    if fixed_cves:
        console.print(f"[green]  Fixed CVEs: {len(fixed_cves)}[/green]")

    console.print(f"\n[cyan]Total scans in history: {len(history['scans'])}[/cyan]")


if __name__ == '__main__':
    main()
