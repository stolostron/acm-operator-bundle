#!/usr/bin/env python3
"""Generate HTML dashboard from CVE trend data"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from load_extras_metadata import load_extras_metadata
from analyze_cve_blast_radius import analyze_blast_radius

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACM CVE Trends - {release}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #d73a49;
            margin-bottom: 10px;
            font-size: 2em;
        }}

        .meta {{
            color: #666;
            margin-bottom: 30px;
            font-size: 0.95em;
        }}

        .meta strong {{
            color: #333;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}

        .chart-container {{
            background: #fafafa;
            padding: 20px;
            border-radius: 6px;
            border: 1px solid #e1e4e8;
        }}

        .chart-container h2 {{
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #24292e;
        }}

        canvas {{
            max-height: 300px;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }}

        .summary-card.critical {{
            background: linear-gradient(135deg, #d73a49 0%, #cb2431 100%);
        }}

        .summary-card.high {{
            background: linear-gradient(135deg, #f66a0a 0%, #e36209 100%);
        }}

        .summary-card.trend {{
            background: linear-gradient(135deg, #28a745 0%, #22863a 100%);
        }}

        .summary-card h3 {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .summary-card p {{
            font-size: 0.9em;
            opacity: 0.9;
        }}

        .component-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 40px;
        }}

        .component-table th,
        .component-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }}

        .component-table th {{
            background: #f6f8fa;
            font-weight: 600;
            color: #24292e;
        }}

        .component-table tr:hover {{
            background: #f6f8fa;
        }}

        .status-red {{
            background: #ffeef0;
        }}

        .status-yellow {{
            background: #fffdef;
        }}

        .status-green {{
            background: #dcffe4;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
        }}

        .severity-critical {{
            background: #d73a49;
            color: white;
        }}

        .severity-high {{
            background: #f66a0a;
            color: white;
        }}

        .timeline {{
            margin-top: 40px;
        }}

        .timeline h2 {{
            font-size: 1.5em;
            margin-bottom: 20px;
            color: #24292e;
        }}

        .timeline ul {{
            list-style: none;
            border-left: 2px solid #e1e4e8;
            padding-left: 20px;
        }}

        .timeline li {{
            margin-bottom: 15px;
            position: relative;
        }}

        .timeline li::before {{
            content: '';
            position: absolute;
            left: -26px;
            top: 6px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #0366d6;
        }}

        .timeline .date {{
            font-weight: 600;
            color: #0366d6;
            margin-right: 10px;
        }}

        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 ACM CVE Trend Dashboard</h1>
        <p class="meta">Release: <strong>{release}</strong> | Updated: {last_updated} | Scans: {scan_count}</p>

        <div class="summary-cards">
            <div class="summary-card critical">
                <h3>{latest_critical}</h3>
                <p>CRITICAL (instances)</p>
            </div>
            <div class="summary-card high">
                <h3>{latest_high}</h3>
                <p>HIGH (instances)</p>
            </div>
            <div class="summary-card">
                <h3>{total_cves}</h3>
                <p>Unique CVEs</p>
                <p style="font-size: 0.8em; margin-top: 5px; opacity: 0.9;">({total_instances} instances)</p>
            </div>
            <div class="summary-card trend">
                <h3>{trend_indicator}</h3>
                <p>Week-over-Week</p>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <h2>📈 CVE Trend Over Time</h2>
                <canvas id="trendChart"></canvas>
            </div>
            <div class="chart-container">
                <h2>🔄 New vs Fixed CVEs</h2>
                <canvas id="deltaChart"></canvas>
            </div>
        </div>

        <h2 style="margin-bottom: 15px;">📊 Component Breakdown</h2>
        <table class="component-table">
            <thead>
                <tr>
                    <th>Component</th>
                    <th style="text-align: center;">CRITICAL</th>
                    <th style="text-align: center;">HIGH</th>
                    <th style="text-align: center;">Total CVEs</th>
                </tr>
            </thead>
            <tbody>
                {component_rows}
            </tbody>
        </table>

        {blast_radius_section}

        {new_cves_section}

        {fixed_cves_section}

        <div class="timeline">
            <h2>📅 Recent Activity</h2>
            <ul>
                {timeline_items}
            </ul>
        </div>
    </div>

    <script>
        {chart_data_js}

        // Trend Chart
        const trendCtx = document.getElementById('trendChart').getContext('2d');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: chartData.labels,
                datasets: [
                    {{
                        label: 'CRITICAL',
                        data: chartData.critical,
                        borderColor: '#d73a49',
                        backgroundColor: 'rgba(215, 58, 73, 0.1)',
                        tension: 0.3,
                        fill: true
                    }},
                    {{
                        label: 'HIGH',
                        data: chartData.high,
                        borderColor: '#f66a0a',
                        backgroundColor: 'rgba(246, 106, 10, 0.1)',
                        tension: 0.3,
                        fill: true
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        // Delta Chart
        const deltaCtx = document.getElementById('deltaChart').getContext('2d');
        new Chart(deltaCtx, {{
            type: 'bar',
            data: {{
                labels: chartData.labels,
                datasets: [
                    {{
                        label: 'New CVEs',
                        data: chartData.newCves,
                        backgroundColor: '#d73a49'
                    }},
                    {{
                        label: 'Fixed CVEs',
                        data: chartData.fixedCves,
                        backgroundColor: '#28a745'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""


def format_timestamp(timestamp_str):
    """Format ISO timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', ''))
        return dt.strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, AttributeError):
        return timestamp_str


def format_date_short(timestamp_str):
    """Format ISO timestamp to short date"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', ''))
        return dt.strftime('%m/%d')
    except (ValueError, AttributeError):
        return timestamp_str


def generate_chart_data(history):
    """Generate JavaScript chart data"""
    scans = history.get('scans', [])[-12:]  # Last 12 weeks

    labels = [format_date_short(scan['timestamp']) for scan in scans]
    critical = [
        scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0)
        for scan in scans
    ]
    high = [
        scan.get('summary', {}).get('by_severity', {}).get('HIGH', 0)
        for scan in scans
    ]
    new_cves = [len(scan.get('new_cves', [])) for scan in scans]
    fixed_cves = [len(scan.get('fixed_cves', [])) for scan in scans]

    chart_data = {
        'labels': labels,
        'critical': critical,
        'high': high,
        'newCves': new_cves,
        'fixedCves': fixed_cves
    }

    return f"const chartData = {json.dumps(chart_data)};"


def generate_component_rows(latest_scan, extras_metadata=None):
    """Generate HTML rows for component table"""
    breakdown = latest_scan.get('summary', {}).get('component_breakdown', {})

    # Sort by total CVEs
    sorted_components = sorted(
        breakdown.items(),
        key=lambda x: x[1].get('total', 0),
        reverse=True
    )[:20]  # Top 20

    rows = []
    for component, counts in sorted_components:
        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        total = counts.get('total', 0)

        # Determine row class
        row_class = ''
        if critical > 5:
            row_class = 'status-red'
        elif critical > 0 or high > 10:
            row_class = 'status-yellow'

        # Get git metadata
        component_display = component
        if extras_metadata and component in extras_metadata:
            meta = extras_metadata[component]
            if meta.get('commit_url'):
                commit_short = meta['git_revision'][:7] if meta.get('git_revision') else ''
                component_display = f'<a href="{meta["commit_url"]}" target="_blank" style="text-decoration: none; color: #0366d6;">{component}</a> <span style="color: #666; font-size: 0.85em;">({commit_short})</span>'

        rows.append(f"""
                <tr class="{row_class}">
                    <td><code>{component_display}</code></td>
                    <td style="text-align: center;"><span class="severity-badge severity-critical">{critical}</span></td>
                    <td style="text-align: center;"><span class="severity-badge severity-high">{high}</span></td>
                    <td style="text-align: center;">{total}</td>
                </tr>""")

    return '\n'.join(rows)


def generate_new_cves_section(latest_scan):
    """Generate HTML section for new CVEs"""
    new_cves = latest_scan.get('new_cves', [])

    # Filter CRITICAL and HIGH
    critical_high = [
        cve for cve in new_cves
        if cve.get('severity') in ['CRITICAL', 'HIGH']
    ]

    if not critical_high:
        return ''

    rows = []
    for cve in critical_high[:15]:  # Top 15
        severity_class = 'severity-' + cve.get('severity', 'unknown').lower()
        fixable = '✓ Yes' if cve.get('fixable') else '✗ No'

        rows.append(f"""
                <tr>
                    <td><code>{cve.get('cve_id', 'Unknown')}</code></td>
                    <td><span class="severity-badge {severity_class}">{cve.get('severity', 'UNKNOWN')}</span></td>
                    <td><code>{cve.get('component', 'unknown')}</code></td>
                    <td>{fixable}</td>
                </tr>""")

    return f"""
        <h2 style="margin: 40px 0 15px 0;">🆕 New CVEs This Week ({len(critical_high)})</h2>
        <table class="component-table">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th>Component</th>
                    <th>Fixable</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    """


def generate_fixed_cves_section(latest_scan):
    """Generate HTML section for fixed CVEs"""
    fixed_cves = latest_scan.get('fixed_cves', [])

    if not fixed_cves:
        return ''

    rows = []
    for cve in fixed_cves[:20]:  # Top 20
        rows.append(f"""
                <tr style="background: #dcffe4;">
                    <td><code>{cve.get('cve_id', 'Unknown')}</code></td>
                    <td><code>{cve.get('component', 'unknown')}</code></td>
                </tr>""")

    return f"""
        <h2 style="margin: 40px 0 15px 0;">✅ Fixed CVEs (Resolved since last scan: {len(fixed_cves)})</h2>
        <table class="component-table">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Component</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    """


def generate_blast_radius_section(latest_scan):
    """Generate blast radius analysis table"""
    blast_radius_data = analyze_blast_radius(latest_scan, top_n=10)

    if not blast_radius_data:
        return ''

    rows = []
    for cve in blast_radius_data:
        severity_class = 'severity-' + cve.get('severity', 'unknown').lower()
        fixable = '✓' if cve.get('fixable') else '✗'
        fixable_color = '#28a745' if cve.get('fixable') else '#666'

        # Get first 3 affected components
        components = cve.get('components', [])[:3]
        component_preview = ', '.join(components)
        if cve.get('component_count', 0) > 3:
            component_preview += f" +{cve.get('component_count') - 3} more"

        # Generate CVE link
        cve_id = cve.get('cve_id', 'Unknown')
        if cve_id.startswith('CVE-'):
            cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" style="text-decoration: none; color: #0366d6;"><code>{cve_id}</code></a>'
        elif cve_id.startswith('GO-'):
            cve_link = f'<a href="https://pkg.go.dev/vuln/{cve_id}" target="_blank" style="text-decoration: none; color: #0366d6;"><code>{cve_id}</code></a>'
        else:
            cve_link = f'<code>{cve_id}</code>'

        fix_available = cve.get('fix_display', 'None')

        rows.append(f"""
                <tr>
                    <td>{cve_link}</td>
                    <td><span class="severity-badge {severity_class}">{cve.get('severity', 'UNKNOWN')}</span></td>
                    <td style="text-align: center;"><strong style="color: #d73a49;">{cve.get('component_count', 0)}</strong></td>
                    <td style="font-size: 0.9em; color: #666;">{component_preview}</td>
                    <td style="text-align: center; color: {fixable_color}; font-size: 0.9em;">{fix_available}</td>
                    <td style="text-align: center; color: {fixable_color}; font-weight: bold;">{fixable}</td>
                </tr>""")

    return f"""
        <h2 style="margin: 40px 0 15px 0;">💥 Highest Blast Radius (CVEs affecting most components)</h2>
        <table class="component-table">
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Severity</th>
                    <th style="text-align: center;">Components</th>
                    <th>Affected Components (preview)</th>
                    <th style="text-align: center;">Fix Available</th>
                    <th style="text-align: center;">Fixable</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    """


def generate_timeline(history):
    """Generate timeline items"""
    scans = history.get('scans', [])[-5:]  # Last 5 scans

    items = []
    for scan in reversed(scans):
        date = format_date_short(scan['timestamp'])
        new_count = len(scan.get('new_cves', []))
        fixed_count = len(scan.get('fixed_cves', []))

        if new_count > 0:
            items.append(f'<li><span class="date">{date}</span> - {new_count} new CVEs detected</li>')
        if fixed_count > 0:
            items.append(f'<li><span class="date">{date}</span> - {fixed_count} CVEs resolved</li>')

    return '\n'.join(items) if items else '<li>No recent activity</li>'


def calculate_trend_indicator(scans):
    """Calculate week-over-week trend indicator"""
    if len(scans) < 2:
        return "—"

    latest = scans[-1].get('summary', {}).get('by_severity', {})
    previous = scans[-2].get('summary', {}).get('by_severity', {})

    latest_total = latest.get('CRITICAL', 0) + latest.get('HIGH', 0)
    previous_total = previous.get('CRITICAL', 0) + previous.get('HIGH', 0)

    delta = latest_total - previous_total

    if delta > 0:
        return f"+{delta}"
    elif delta < 0:
        return str(delta)
    else:
        return "0"


def main():
    parser = argparse.ArgumentParser(description='Generate HTML CVE trend dashboard')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory (default: reports)')
    parser.add_argument('--release', required=True,
                       help='Release name (e.g., release-2.17)')
    parser.add_argument('--output',
                       help='Output HTML file path (default: reports/trends/{release}-dashboard.html)')

    args = parser.parse_args()

    # Load history
    history_file = Path(args.reports_dir) / 'trends' / f"{args.release}-history.json"

    if not history_file.exists():
        console.print(f"[red]History file not found: {history_file}[/red]")
        console.print("[yellow]Run a scan first to generate history data[/yellow]")
        sys.exit(1)

    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Error loading history: {e}[/red]")
        sys.exit(1)

    scans = history.get('scans', [])

    if not scans:
        console.print("[yellow]No scan data available[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]Generating HTML dashboard for {args.release}...[/cyan]")

    # Load git metadata from extras
    extras_metadata = load_extras_metadata()

    # Get latest scan
    latest_scan = scans[-1]
    latest_severity = latest_scan.get('summary', {}).get('by_severity', {})

    # Generate HTML components
    html = HTML_TEMPLATE.format(
        release=args.release,
        last_updated=format_timestamp(latest_scan['timestamp']),
        scan_count=len(scans),
        latest_critical=latest_severity.get('CRITICAL', 0),
        latest_high=latest_severity.get('HIGH', 0),
        total_cves=latest_scan.get('summary', {}).get('total_cves', 0),
        total_instances=latest_scan.get('summary', {}).get('total_matches', 0),
        trend_indicator=calculate_trend_indicator(scans),
        chart_data_js=generate_chart_data(history),
        component_rows=generate_component_rows(latest_scan, extras_metadata),
        blast_radius_section=generate_blast_radius_section(latest_scan),
        new_cves_section=generate_new_cves_section(latest_scan),
        fixed_cves_section=generate_fixed_cves_section(latest_scan),
        timeline_items=generate_timeline(history)
    )

    # Determine output path
    output_path = args.output
    if not output_path:
        output_path = Path(args.reports_dir) / 'trends' / f"{args.release}-dashboard.html"
    else:
        output_path = Path(output_path)

    # Ensure directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write HTML
    try:
        with open(output_path, 'w') as f:
            f.write(html)
        console.print(f"[green]✓ Dashboard generated: {output_path}[/green]")
    except (OSError, PermissionError) as e:
        console.print(f"[red]Error writing HTML: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
