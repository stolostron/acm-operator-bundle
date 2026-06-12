#!/usr/bin/env python3
"""Store CVE scan results for historical trend tracking"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

console = Console()


def load_history(history_file):
    """Load existing scan history or create new structure"""
    if not history_file.exists():
        return {
            "release": None,
            "version": None,
            "scans": [],
            "metadata": {
                "created": datetime.now(timezone.utc).isoformat() + "Z",
                "last_updated": None,
                "scan_frequency": "weekly",
                "retention_weeks": 26,
                "max_scans": 4
            }
        }

    try:
        with open(history_file, 'r') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading history file: {e}[/red]")
        sys.exit(1)


def extract_image_key_from_filename(filepath):
    """Extract image key from grype JSON filename

    Example: 2.17.0_klusterlet_addon_controller_grype.json -> klusterlet_addon_controller
    """
    filename = Path(filepath).name
    # Remove version prefix and _grype.json suffix
    # Pattern: {version}_{image_key}_grype.json
    parts = filename.replace('_grype.json', '').split('_')
    # First part is version (e.g., 2.17.0), rest is image key
    if len(parts) > 1:
        return '_'.join(parts[1:])
    return 'unknown'


def extract_scan_summary_from_all(reports_dir):
    """Extract summary statistics from all Grype JSON reports, grouped by image

    Args:
        reports_dir: Path to reports directory

    Returns:
        dict with overall stats and per-image component_breakdown
    """
    reports_path = Path(reports_dir)
    json_files = list(reports_path.rglob('*_grype.json'))

    if not json_files:
        console.print(f"[yellow]Warning: No Grype JSON files found in {reports_dir}[/yellow]")
        return {
            'total_cves': 0,
            'total_matches': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NEGLIGIBLE': 0, 'UNKNOWN': 0},
            'component_breakdown': {},
            'cve_details': []
        }

    # Global counters
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NEGLIGIBLE': 0, 'UNKNOWN': 0}
    global_cve_set = set()
    total_matches = 0
    component_breakdown = {}  # keyed by image_key
    all_cve_details = []

    for json_file in json_files:
        image_key = extract_image_key_from_filename(json_file)

        try:
            with open(json_file, 'r') as f:
                scan_report = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[yellow]Warning: Could not read {json_file}: {e}[/yellow]")
            continue

        matches = scan_report.get('matches', [])
        total_matches += len(matches)

        # Initialize image entry
        if image_key not in component_breakdown:
            component_breakdown[image_key] = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'total': 0
            }

        for match in matches:
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})

            cve_id = vuln.get('id', 'UNKNOWN')
            severity = vuln.get('severity', 'UNKNOWN').upper()
            package_name = artifact.get('name', 'unknown')

            # Count by severity globally
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Track unique CVEs globally
            global_cve_set.add(cve_id)

            # Count by severity per image
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                component_breakdown[image_key][severity] += 1
            component_breakdown[image_key]['total'] += 1

            # Store CVE details with image context
            all_cve_details.append({
                'cve_id': cve_id,
                'severity': severity,
                'component': image_key,  # Now this is the image, not the package
                'package': package_name,
                'fixed_versions': vuln.get('fix', {}).get('versions', []),
                'fixable': len(vuln.get('fix', {}).get('versions', [])) > 0
            })

    return {
        'total_cves': len(global_cve_set),
        'total_matches': total_matches,
        'by_severity': severity_counts,
        'component_breakdown': component_breakdown,
        'cve_details': all_cve_details
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
    """Auto-detect release version from extras directory

    Returns:
        tuple: (release_name, full_version) e.g., ('release-2.17', '2.17.0')
    """
    extras_path = Path(extras_dir)
    if not extras_path.exists():
        return None, None

    # Look for version pattern in JSON filenames (e.g., 2.17.0.json)
    for json_file in extras_path.glob('*.json'):
        name = json_file.stem
        parts = name.split('.')
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            # Return both release-X.Y and full X.Y.Z
            release_name = f"release-{parts[0]}.{parts[1]}"
            full_version = name  # e.g., "2.17.0"
            return release_name, full_version

    return None, None


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
        cutoff = datetime.now(timezone.utc).timestamp() - (retention_weeks * 7 * 24 * 60 * 60)
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
    full_version = None
    if not release:
        release, full_version = detect_release_from_extras(args.extras_dir)
        if not release:
            console.print("[red]Could not auto-detect release. Use --release flag[/red]")
            sys.exit(1)
    else:
        # Manual release specified, try to get version from extras
        _, full_version = detect_release_from_extras(args.extras_dir)

    console.print(f"[cyan]Storing scan results for {release}[/cyan]")
    if full_version:
        console.print(f"[cyan]Version: {full_version}[/cyan]")

    # Extract summary from all Grype JSON files
    console.print(f"[cyan]Processing all Grype scan results in {args.reports_dir}[/cyan]")
    summary = extract_scan_summary_from_all(args.reports_dir)

    # Load or create history
    trends_dir = Path(args.reports_dir) / 'trends'
    trends_dir.mkdir(parents=True, exist_ok=True)

    history_file = trends_dir / f"{release}-history.json"
    history = load_history(history_file)

    # Set release name and version if new history
    if not history.get('release'):
        history['release'] = release
    if full_version and not history.get('version'):
        history['version'] = full_version

    # Get previous scan for comparison
    previous_scan = history['scans'][-1]['summary'] if history.get('scans') else None

    # Detect new and fixed CVEs
    new_cves, fixed_cves = detect_changes(summary, previous_scan)

    # Create scan record
    scan_record = {
        'timestamp': datetime.now(timezone.utc).isoformat() + 'Z',
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
    history['metadata']['last_updated'] = datetime.now(timezone.utc).isoformat() + 'Z'

    # Prune old scans
    retention_weeks = history['metadata'].get('retention_weeks', 26)
    max_scans = history['metadata'].get('max_scans', 4)
    prune_old_scans(history, retention_weeks=retention_weeks, max_scans=max_scans)

    # Save history
    try:
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
        console.print(f"[green]✓ Scan results stored: {history_file}[/green]")
    except (OSError, json.JSONDecodeError) as e:
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
