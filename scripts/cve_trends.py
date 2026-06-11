#!/usr/bin/env python3
"""Generate CVE trend analysis from historical scan data"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def load_history(history_file):
    """Load scan history from JSON file"""
    if not history_file.exists():
        console.print(f"[red]History file not found: {history_file}[/red]")
        console.print("[yellow]Run a scan first to generate history data[/yellow]")
        sys.exit(1)

    try:
        with open(history_file, 'r') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading history: {e}[/red]")
        sys.exit(1)


def calculate_trend_direction(current, previous):
    """Calculate trend direction and status"""
    if previous is None:
        return "→", "🟡 New"

    delta = current - previous
    if delta > 0:
        return f"+{delta}↑", "🔴 Worse"
    elif delta < 0:
        return f"{delta}↓", "🟢 Better"
    else:
        return "0→", "🟡 Same"


def format_timestamp(timestamp_str):
    """Format ISO timestamp to readable date"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', ''))
        return dt.strftime('%Y-%m-%d')
    except (ValueError, AttributeError):
        return timestamp_str


def get_top_offenders(history, limit=10):
    """Calculate top components by CVE count across all scans"""
    component_totals = {}

    for scan in history.get('scans', []):
        breakdown = scan.get('summary', {}).get('component_breakdown', {})

        for component, counts in breakdown.items():
            if component not in component_totals:
                component_totals[component] = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'total': 0
                }

            component_totals[component]['CRITICAL'] += counts.get('CRITICAL', 0)
            component_totals[component]['HIGH'] += counts.get('HIGH', 0)
            component_totals[component]['total'] += counts.get('total', 0)

    # Sort by total CVEs
    sorted_components = sorted(
        component_totals.items(),
        key=lambda x: x[1]['total'],
        reverse=True
    )

    return sorted_components[:limit]


def print_trend_summary(history, weeks=8):
    """Print weekly trend summary table"""
    scans = history.get('scans', [])[-weeks:]

    if not scans:
        console.print("[yellow]No scan data available[/yellow]")
        return

    release = history.get('release', 'Unknown')

    # Header panel
    period_start = format_timestamp(scans[0]['timestamp'])
    period_end = format_timestamp(scans[-1]['timestamp'])

    header = Panel(
        f"[bold]CVE Trend Report - {release}[/bold]\n"
        f"Period: Last {len(scans)} weeks ({period_start} to {period_end})",
        border_style="cyan"
    )
    console.print(header)

    # Trend summary table
    console.print("\n📈 [bold]Trend Summary[/bold]")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Week", style="dim")
    table.add_column("CRITICAL", justify="center")
    table.add_column("HIGH", justify="center")
    table.add_column("Change", justify="center")
    table.add_column("Status")

    previous_total = None

    for scan in scans:
        timestamp = format_timestamp(scan['timestamp'])
        severity = scan.get('summary', {}).get('by_severity', {})

        critical = severity.get('CRITICAL', 0)
        high = severity.get('HIGH', 0)
        current_total = critical + high

        change_str, status = calculate_trend_direction(current_total, previous_total)

        table.add_row(
            timestamp,
            str(critical),
            str(high),
            change_str,
            status
        )

        previous_total = current_total

    console.print(table)


def print_new_cves(latest_scan):
    """Print new CVEs from latest scan"""
    new_cves = latest_scan.get('new_cves', [])

    if not new_cves:
        console.print("\n[green]✓ No new CVEs detected[/green]")
        return

    # Filter to CRITICAL and HIGH only
    critical_high = [
        cve for cve in new_cves
        if cve.get('severity') in ['CRITICAL', 'HIGH']
    ]

    if not critical_high:
        console.print(f"\n[dim]ℹ️  {len(new_cves)} new CVEs (none CRITICAL/HIGH)[/dim]")
        return

    console.print(f"\n🔍 [bold]New CVEs This Week ({len(critical_high)})[/bold]")

    table = Table(show_header=True, header_style="bold yellow")
    table.add_column("CVE ID", style="yellow")
    table.add_column("Severity", justify="center")
    table.add_column("Component", style="cyan")
    table.add_column("Fixable", justify="center")

    for cve in critical_high[:20]:  # Limit to 20 for display
        fixable = "✓ Yes" if cve.get('fixable') else "✗ No"

        table.add_row(
            cve.get('cve_id', 'Unknown'),
            cve.get('severity', 'UNKNOWN'),
            cve.get('component', 'unknown')[:30],  # Truncate long component names
            fixable
        )

    console.print(table)

    if len(critical_high) > 20:
        console.print(f"[dim]... and {len(critical_high) - 20} more[/dim]")


def print_fixed_cves(latest_scan):
    """Print fixed CVEs from latest scan"""
    fixed_cves = latest_scan.get('fixed_cves', [])

    if not fixed_cves:
        return

    console.print(f"\n✅ [bold]Fixed CVEs (Resolved since last scan)[/bold]")

    for cve in fixed_cves[:10]:  # Limit to 10
        cve_id = cve.get('cve_id', 'Unknown')
        component = cve.get('component', 'unknown')
        console.print(f"  • {cve_id} in {component}")

    if len(fixed_cves) > 10:
        console.print(f"[dim]  ... and {len(fixed_cves) - 10} more[/dim]")


def print_top_offenders(history):
    """Print top offending components"""
    top = get_top_offenders(history, limit=10)

    if not top:
        return

    console.print("\n🏆 [bold]Top Offenders (by CVE count over period)[/bold]")

    for i, (component, counts) in enumerate(top, 1):
        console.print(
            f"  {i}. {component}: {counts['total']} total CVEs "
            f"({counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH)"
        )


def print_statistics(history):
    """Print overall statistics"""
    scans = history.get('scans', [])

    if len(scans) < 2:
        return

    console.print("\n📊 [bold]Stats[/bold]")

    # Calculate averages
    total_critical = sum(
        scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0)
        for scan in scans
    )
    total_high = sum(
        scan.get('summary', {}).get('by_severity', {}).get('HIGH', 0)
        for scan in scans
    )

    avg_critical = total_critical / len(scans)
    avg_high = total_high / len(scans)

    console.print(f"  • Total scans: {len(scans)}")
    console.print(f"  • Avg CRITICAL per week: {avg_critical:.1f}")
    console.print(f"  • Avg HIGH per week: {avg_high:.1f}")

    # Compare first and last
    if len(scans) >= 4:
        first_half = scans[:len(scans)//2]
        second_half = scans[len(scans)//2:]

        first_avg = sum(
            scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0)
            for scan in first_half
        ) / len(first_half)

        second_avg = sum(
            scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0)
            for scan in second_half
        ) / len(second_half)

        if second_avg > first_avg:
            trend_text = f"🔴 Worsening ({second_avg:.0f} vs {first_avg:.0f} in first half)"
        elif second_avg < first_avg:
            trend_text = f"🟢 Improving ({second_avg:.0f} vs {first_avg:.0f} in first half)"
        else:
            trend_text = "🟡 Stable"

        console.print(f"  • Trending: {trend_text}")


def main():
    parser = argparse.ArgumentParser(description='Generate CVE trend analysis')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory (default: reports)')
    parser.add_argument('--release', required=True,
                       help='Release name (e.g., release-2.17)')
    parser.add_argument('--weeks', type=int, default=8,
                       help='Number of weeks to show in trend (default: 8)')
    parser.add_argument('--format', choices=['table', 'json'], default='table',
                       help='Output format (default: table)')

    args = parser.parse_args()

    # Load history
    history_file = Path(args.reports_dir) / 'trends' / f"{args.release}-history.json"
    history = load_history(history_file)

    scans = history.get('scans', [])

    if not scans:
        console.print("[yellow]No scan data available[/yellow]")
        sys.exit(0)

    if args.format == 'json':
        # Output raw JSON
        print(json.dumps(history, indent=2))
        return

    # Print formatted report
    print_trend_summary(history, weeks=args.weeks)

    # Latest scan details
    latest_scan = scans[-1]

    print_new_cves(latest_scan)
    print_fixed_cves(latest_scan)
    print_top_offenders(history)
    print_statistics(history)

    console.print()  # Blank line at end


if __name__ == '__main__':
    main()
