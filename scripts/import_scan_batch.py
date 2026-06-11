#!/usr/bin/env python3
"""Import batch of Grype JSON scans into trend history"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console

console = Console()


def aggregate_scan_results(json_dir):
    """Aggregate all component scans from a directory into single summary"""
    json_path = Path(json_dir)

    if not json_path.exists():
        console.print(f"[red]Directory not found: {json_dir}[/red]")
        return None

    # Find all Grype JSON files
    grype_files = list(json_path.glob('*_grype.json'))

    if not grype_files:
        console.print(f"[yellow]No Grype JSON files found in {json_dir}[/yellow]")
        return None

    console.print(f"[cyan]Found {len(grype_files)} component scans[/cyan]")

    # Aggregate CVEs across all components
    all_cves = set()
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NEGLIGIBLE': 0, 'UNKNOWN': 0}
    component_breakdown = {}
    all_cve_details = []

    for grype_file in grype_files:
        # Extract component name from filename
        component_name = grype_file.stem.replace('_grype', '').split('_', 1)[1] if '_' in grype_file.stem else grype_file.stem

        try:
            with open(grype_file, 'r') as f:
                scan_data = json.load(f)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to load {grype_file.name}: {e}[/yellow]")
            continue

        matches = scan_data.get('matches', [])

        # Track per-component CVEs
        if component_name not in component_breakdown:
            component_breakdown[component_name] = {
                'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'total': 0
            }

        for match in matches:
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})

            cve_id = vuln.get('id', 'UNKNOWN')
            severity = vuln.get('severity', 'UNKNOWN').upper()

            # Add to global CVE set
            all_cves.add(cve_id)

            # Count by severity
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Count per-component
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                component_breakdown[component_name][severity] += 1
            component_breakdown[component_name]['total'] += 1

            # Store CVE details
            all_cve_details.append({
                'cve_id': cve_id,
                'severity': severity,
                'component': component_name,
                'fixed_versions': vuln.get('fix', {}).get('versions', []),
                'fixable': len(vuln.get('fix', {}).get('versions', [])) > 0
            })

    return {
        'total_cves': len(all_cves),
        'total_matches': sum(severity_counts.values()),
        'by_severity': severity_counts,
        'component_breakdown': component_breakdown,
        'cve_details': all_cve_details
    }


def main():
    parser = argparse.ArgumentParser(description='Import batch scan results into trend history')
    parser.add_argument('--json-dir', required=True,
                       help='Directory containing Grype JSON files (e.g., reports/2.17.0/json/)')
    parser.add_argument('--release', required=True,
                       help='Release name (e.g., release-2.17)')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory (default: reports)')
    parser.add_argument('--timestamp',
                       help='ISO timestamp for this scan (default: now)')
    parser.add_argument('--github-run-id',
                       help='GitHub Actions run ID')

    args = parser.parse_args()

    console.print(f"[cyan]Aggregating scans from {args.json_dir}...[/cyan]")

    # Aggregate all component scans
    summary = aggregate_scan_results(args.json_dir)

    if not summary:
        console.print("[red]Failed to aggregate scan results[/red]")
        sys.exit(1)

    console.print(f"[green]✓ Aggregated {summary['total_cves']} unique CVEs across {len(summary['component_breakdown'])} components[/green]")

    # Load or create history
    trends_dir = Path(args.reports_dir) / 'trends'
    trends_dir.mkdir(parents=True, exist_ok=True)

    history_file = trends_dir / f"{args.release}-history.json"

    if history_file.exists():
        with open(history_file, 'r') as f:
            history = json.load(f)
    else:
        history = {
            "release": args.release,
            "scans": [],
            "metadata": {
                "created": datetime.utcnow().isoformat() + "Z",
                "last_updated": None,
                "scan_frequency": "weekly",
                "retention_weeks": 26
            }
        }

    # Get previous scan for comparison
    previous_scan = history['scans'][-1]['summary'] if history.get('scans') else None

    # Detect new and fixed CVEs
    new_cves = []
    fixed_cves = []

    if previous_scan:
        current_cve_set = {
            (cve['cve_id'], cve['component'])
            for cve in summary['cve_details']
        }

        previous_cve_set = {
            (cve['cve_id'], cve['component'])
            for cve in previous_scan.get('cve_details', [])
        }

        # New CVEs
        new_cve_keys = current_cve_set - previous_cve_set
        new_cves = [
            cve for cve in summary['cve_details']
            if (cve['cve_id'], cve['component']) in new_cve_keys
        ]

        # Fixed CVEs
        fixed_cve_keys = previous_cve_set - current_cve_set
        fixed_cves = [
            {'cve_id': cve_id, 'component': component}
            for cve_id, component in fixed_cve_keys
        ]

    # Create scan record
    scan_record = {
        'timestamp': args.timestamp or (datetime.utcnow().isoformat() + 'Z'),
        'json_dir': args.json_dir,
        'github_run_id': args.github_run_id,
        'summary': {
            'total_cves': summary['total_cves'],
            'total_matches': summary['total_matches'],
            'by_severity': summary['by_severity'],
            'component_breakdown': summary['component_breakdown'],
            'cve_details': summary['cve_details']  # Keep for next scan comparison
        },
        'new_cves': new_cves,
        'fixed_cves': fixed_cves
    }

    # Append to history
    history['scans'].append(scan_record)
    history['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'

    # Save history
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)

    console.print(f"[green]✓ Scan added to history: {history_file}[/green]")
    console.print(f"\n[bold]Summary[/bold]")
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
