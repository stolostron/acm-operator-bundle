#!/usr/bin/env python3
"""Generate multi-release CVE trend dashboard with tabs"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from load_extras_metadata import load_extras_metadata
from analyze_cve_blast_radius import analyze_blast_radius
from load_cve_descriptions import load_cve_descriptions

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACM CVE Trends - All Releases</title>
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
            line-height: 1.6;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}

        .header .meta {{
            opacity: 0.9;
            font-size: 0.95em;
        }}

        .tabs {{
            background: white;
            padding: 0;
            display: flex;
            border-bottom: 2px solid #e1e4e8;
            overflow-x: auto;
        }}

        .tab {{
            padding: 15px 25px;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 1em;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
            white-space: nowrap;
        }}

        .tab:hover {{
            background: #f6f8fa;
            color: #333;
        }}

        .tab.active {{
            color: #0366d6;
            border-bottom-color: #0366d6;
            font-weight: 600;
        }}

        .tab-content {{
            display: none;
            padding: 30px;
            max-width: 1400px;
            margin: 0 auto;
        }}

        .tab-content.active {{
            display: block;
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

        .summary-card.trend.worsening {{
            background: linear-gradient(135deg, #d73a49 0%, #cb2431 100%);
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

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}

        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        .chart-container h2 {{
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #24292e;
        }}

        canvas {{
            max-height: 300px;
        }}

        .component-table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
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
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 25px;
        }}

        .component-table th:hover {{
            background: #e1e4e8;
        }}

        .component-table th::after {{
            content: '⇅';
            position: absolute;
            right: 8px;
            opacity: 0.3;
        }}

        .component-table th.sort-asc::after {{
            content: '▲';
            opacity: 1;
        }}

        .component-table th.sort-desc::after {{
            content: '▼';
            opacity: 1;
        }}

        .component-table tr:hover {{
            background: #f6f8fa;
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

        .no-data {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}

        .no-data h2 {{
            font-size: 1.5em;
            margin-bottom: 10px;
        }}

        .show-all-btn {{
            margin: 15px 0 30px 0;
            padding: 10px 20px;
            background: #0366d6;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: 600;
        }}

        .show-all-btn:hover {{
            background: #0256c5;
        }}

        .component-row-hidden {{
            display: none;
        }}

        .cve-tooltip {{
            position: relative;
            cursor: help;
        }}

        .cve-tooltip .tooltiptext {{
            visibility: hidden;
            width: 450px;
            background-color: #24292e;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 15px;
            position: absolute;
            z-index: 1000;
            top: -10px;
            left: 120%;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.9em;
            line-height: 1.5;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}

        .cve-tooltip .tooltiptext::after {{
            content: "";
            position: absolute;
            top: 20px;
            right: 100%;
            margin-top: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: transparent #24292e transparent transparent;
        }}

        .cve-tooltip:hover .tooltiptext {{
            visibility: visible;
            opacity: 1;
        }}

        .tooltip-title {{
            font-weight: bold;
            margin-bottom: 8px;
            color: #58a6ff;
        }}

        .tooltip-cvss {{
            color: #f85149;
            font-weight: 600;
            margin-bottom: 8px;
        }}

        /* Component drill-down modal */
        .modal {{
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.6);
        }}

        .modal-content {{
            background-color: #fefefe;
            margin: 5% auto;
            padding: 0;
            border: 1px solid #888;
            width: 90%;
            max-width: 1000px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            max-height: 85vh;
            overflow-y: auto;
        }}

        .modal-header {{
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px 8px 0 0;
        }}

        .modal-header h2 {{
            margin: 0;
            font-size: 1.5em;
        }}

        .modal-body {{
            padding: 20px;
        }}

        .close {{
            color: white;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}

        .close:hover,
        .close:focus {{
            color: #ddd;
        }}

        .component-link {{
            cursor: pointer;
            text-decoration: underline;
            color: #0366d6;
        }}

        .component-link:hover {{
            color: #0256c5;
        }}

        /* Compare All tab specific styles */
        .comparison-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .release-card {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        .release-card h3 {{
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #24292e;
        }}

        .release-card .stat {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e1e4e8;
        }}

        .release-card .stat:last-child {{
            border-bottom: none;
        }}

        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            .comparison-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 ACM CVE Trend Dashboard</h1>
        <p class="meta">Multi-Release Analysis | Updated: {timestamp}</p>
    </div>

    <div class="tabs">
        <button class="tab active" onclick="openTab(event, 'compare-all')">📊 Compare All</button>
        {tab_buttons}
    </div>

    <div id="compare-all" class="tab-content active">
        <h2 style="margin-bottom: 20px; font-size: 1.8em;">Release Comparison</h2>
        <div class="comparison-grid">
            {comparison_cards}
        </div>

        <div class="chart-container" style="margin-bottom: 30px;">
            <h2>All Releases - Latest CVE Counts</h2>
            <canvas id="compareChart"></canvas>
        </div>
    </div>

    {tab_contents}

    <!-- Component CVE Detail Modal -->
    <div id="cveModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close" onclick="closeModal()">&times;</span>
                <h2 id="modalTitle">Component CVEs</h2>
            </div>
            <div class="modal-body">
                <div id="modalContent"></div>
            </div>
        </div>
    </div>

    <script>
        {chart_data_js}

        {component_cve_data_js}

        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }}
            tablinks = document.getElementsByClassName("tab");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }}

        function sortTable(tabId, columnIndex, type) {{
            const table = document.getElementById('componentTable-' + tabId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];

            // Determine sort direction
            const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                               header.classList.contains('sort-desc') ? 'desc' : 'none';
            const newSort = currentSort === 'asc' ? 'desc' : 'asc';

            // Remove all sort classes
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});

            // Add new sort class
            header.classList.add('sort-' + newSort);

            // Sort rows
            rows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    // Use data attributes for numeric sorting
                    const dataAttr = ['component', 'critical', 'high', 'total'][columnIndex];
                    aVal = parseInt(a.dataset[dataAttr] || 0);
                    bVal = parseInt(b.dataset[dataAttr] || 0);
                }} else {{
                    // Text sorting
                    aVal = a.cells[columnIndex].textContent.trim().toLowerCase();
                    bVal = b.cells[columnIndex].textContent.trim().toLowerCase();
                }}

                if (newSort === 'asc') {{
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                }} else {{
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }}
            }});

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}

        function sortExternalTable(tabId, columnIndex, type) {{
            const table = document.getElementById('externalTable-' + tabId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];

            // Determine sort direction
            const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                               header.classList.contains('sort-desc') ? 'desc' : 'none';
            const newSort = currentSort === 'asc' ? 'desc' : 'asc';

            // Remove all sort classes
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});

            // Add new sort class
            header.classList.add('sort-' + newSort);

            // Sort rows
            rows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    const dataAttr = ['component', 'critical', 'high', 'total'][columnIndex];
                    aVal = parseInt(a.dataset[dataAttr] || 0);
                    bVal = parseInt(b.dataset[dataAttr] || 0);
                }} else {{
                    aVal = a.cells[columnIndex].textContent.trim().toLowerCase();
                    bVal = b.cells[columnIndex].textContent.trim().toLowerCase();
                }}

                if (newSort === 'asc') {{
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                }} else {{
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }}
            }});

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}

        function sortFixedTable(tabId, columnIndex) {{
            const table = document.getElementById('fixedTable-' + tabId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];

            // Determine sort direction
            const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                               header.classList.contains('sort-desc') ? 'desc' : 'none';
            const newSort = currentSort === 'asc' ? 'desc' : 'asc';

            // Remove all sort classes
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});

            // Add new sort class
            header.classList.add('sort-' + newSort);

            // Sort rows
            rows.sort((a, b) => {{
                const dataAttr = columnIndex === 0 ? 'cve' : 'component';
                const aVal = a.dataset[dataAttr].toLowerCase();
                const bVal = b.dataset[dataAttr].toLowerCase();

                if (newSort === 'asc') {{
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                }} else {{
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }}
            }});

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}

        function sortBlastTable(tabId, columnIndex, type) {{
            const table = document.getElementById('blastTable-' + tabId);
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];

            // Determine sort direction
            const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                               header.classList.contains('sort-desc') ? 'desc' : 'none';
            const newSort = currentSort === 'asc' ? 'desc' : 'asc';

            // Remove all sort classes
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});

            // Add new sort class
            header.classList.add('sort-' + newSort);

            // Sort rows
            rows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    const dataAttr = ['cve', 'severity', 'cvss', 'count', '', '', 'fixable'][columnIndex];
                    aVal = parseFloat(a.dataset[dataAttr] || 0);
                    bVal = parseFloat(b.dataset[dataAttr] || 0);
                }} else {{
                    aVal = a.cells[columnIndex].textContent.trim().toLowerCase();
                    bVal = b.cells[columnIndex].textContent.trim().toLowerCase();
                }}

                if (newSort === 'asc') {{
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                }} else {{
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }}
            }});

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}

        function sortModalTable(tableId, columnIndex, type) {{
            const table = document.getElementById(tableId);
            if (!table) return;

            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const header = table.querySelectorAll('th')[columnIndex];

            // Determine sort direction
            const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                               header.classList.contains('sort-desc') ? 'desc' : 'none';
            const newSort = currentSort === 'asc' ? 'desc' : 'asc';

            // Remove all sort classes
            table.querySelectorAll('th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
            }});

            // Add new sort class
            header.classList.add('sort-' + newSort);

            // Sort rows
            rows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    const dataAttr = ['cve', 'severity', 'cvss', 'description', 'fix'][columnIndex];
                    aVal = parseFloat(a.dataset[dataAttr] || 0);
                    bVal = parseFloat(b.dataset[dataAttr] || 0);
                }} else {{
                    aVal = a.cells[columnIndex].textContent.trim().toLowerCase();
                    bVal = b.cells[columnIndex].textContent.trim().toLowerCase();
                }}

                if (newSort === 'asc') {{
                    return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                }} else {{
                    return aVal < bVal ? 1 : aVal > bVal ? -1 : 0;
                }}
            }});

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }}

        function closeModal() {{
            document.getElementById('cveModal').style.display = 'none';
        }}

        function showComponentCVEs(component, tabId) {{
            const modal = document.getElementById('cveModal');
            const title = document.getElementById('modalTitle');
            const content = document.getElementById('modalContent');

            title.textContent = `CVEs for ${{component}}`;

            // Get CVE data for this component
            const componentData = window.componentCVEData[tabId][component];

            if (!componentData || componentData.length === 0) {{
                content.innerHTML = '<p>No CVE data available for this component.</p>';
                modal.style.display = 'block';
                return;
            }}

            // Build CVE table with sorting
            const tableId = 'modalTable-' + component.replace(/[^a-zA-Z0-9]/g, '_');
            let html = `
                <p><strong>${{componentData.length}} CVEs found</strong></p>
                <table class="component-table" id="${{tableId}}">
                    <thead>
                        <tr>
                            <th onclick="sortModalTable('${{tableId}}', 0, 'string')">CVE ID</th>
                            <th onclick="sortModalTable('${{tableId}}', 1, 'number')">Severity</th>
                            <th onclick="sortModalTable('${{tableId}}', 2, 'number')">CVSS</th>
                            <th onclick="sortModalTable('${{tableId}}', 3, 'string')">Description</th>
                            <th onclick="sortModalTable('${{tableId}}', 4, 'string')">Fix Available</th>
                        </tr>
                    </thead>
                    <tbody>`;

            const severityOrder = {{'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}};

            componentData.forEach(cve => {{
                const cvssDisplay = cve.cvss_score ? cve.cvss_score.toFixed(1) : '—';
                const cvssValue = cve.cvss_score || 0;
                const cvssColor = cve.cvss_score >= 9 ? '#d73a49' : cve.cvss_score >= 7 ? '#f66a0a' : '#666';
                const severityClass = 'severity-' + cve.severity.toLowerCase();
                const severityValue = severityOrder[cve.severity] || 0;
                const description = cve.description.substring(0, 150) + (cve.description.length > 150 ? '...' : '');

                let cveLink;
                if (cve.cve_id.startsWith('CVE-')) {{
                    cveLink = `<a href="https://nvd.nist.gov/vuln/detail/${{cve.cve_id}}" target="_blank"><code>${{cve.cve_id}}</code></a>`;
                }} else if (cve.cve_id.startsWith('GO-')) {{
                    cveLink = `<a href="https://pkg.go.dev/vuln/${{cve.cve_id}}" target="_blank"><code>${{cve.cve_id}}</code></a>`;
                }} else {{
                    cveLink = `<code>${{cve.cve_id}}</code>`;
                }}

                html += `
                    <tr data-cve="${{cve.cve_id}}" data-severity="${{severityValue}}" data-cvss="${{cvssValue}}" data-description="${{description}}" data-fix="${{cve.fix_display}}">
                        <td>${{cveLink}}</td>
                        <td><span class="severity-badge ${{severityClass}}">${{cve.severity}}</span></td>
                        <td style="text-align: center; color: ${{cvssColor}}; font-weight: 700;">${{cvssDisplay}}</td>
                        <td style="font-size: 0.9em;">${{description}}</td>
                        <td style="text-align: center; font-size: 0.9em;">${{cve.fix_display}}</td>
                    </tr>`;
            }});

            html += `
                    </tbody>
                </table>`;

            content.innerHTML = html;
            modal.style.display = 'block';
        }}

        // Close modal when clicking outside
        window.onclick = function(event) {{
            const modal = document.getElementById('cveModal');
            if (event.target == modal) {{
                modal.style.display = 'none';
            }}
        }}

        // Attach click handlers to component links (prevents XSS from inline onclick)
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.component-link').forEach(link => {{
                link.addEventListener('click', function() {{
                    const component = this.getAttribute('data-component');
                    const tabId = this.getAttribute('data-tab');
                    showComponentCVEs(component, tabId);
                }});
            }});
        }});

        function toggleShowAll(tabId, tableType) {{
            const tableId = tableType === 'internal' ? 'componentTable-' + tabId : 'externalTable-' + tabId;
            const table = document.getElementById(tableId);
            const hiddenRows = table.querySelectorAll('.component-row-hidden');
            const btn = event.target;

            if (hiddenRows.length > 0 && hiddenRows[0].style.display === 'none' || !hiddenRows[0].style.display) {{
                // Show all
                hiddenRows.forEach(row => row.style.display = 'table-row');
                btn.textContent = btn.textContent.replace('Show All', 'Show Top 15');
            }} else {{
                // Hide extras
                hiddenRows.forEach(row => row.style.display = 'none');
                const total = btn.textContent.match(/\\d+/)[0];
                btn.textContent = `Show All ${{tableType === 'internal' ? 'Internal' : 'External'}} (${{total}} total)`;
            }}
        }}

        // Comparison chart
        if (compareData) {{
            const compareCtx = document.getElementById('compareChart').getContext('2d');
            new Chart(compareCtx, {{
                type: 'bar',
                data: {{
                    labels: compareData.labels,
                    datasets: [
                        {{
                            label: 'CRITICAL',
                            data: compareData.critical,
                            backgroundColor: '#d73a49'
                        }},
                        {{
                            label: 'HIGH',
                            data: compareData.high,
                            backgroundColor: '#f66a0a'
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
                        x: {{
                            stacked: true
                        }},
                        y: {{
                            stacked: true,
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        }}

        // Individual release charts
        {individual_charts_js}
    </script>
</body>
</html>
"""


def format_timestamp(timestamp_str):
    """Format ISO timestamp"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', ''))
        return dt.strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, AttributeError):
        return timestamp_str


def format_date_short(timestamp_str):
    """Return ISO timestamp for client-side local timezone conversion"""
    try:
        # Clean malformed timestamps: remove Z if timezone offset present
        if '+' in timestamp_str and timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str[:-1]
        return timestamp_str
    except (ValueError, AttributeError):
        return timestamp_str


def load_release_history(trends_dir, release):
    """Load history file for a release"""
    history_file = trends_dir / f"{release}-history.json"

    if not history_file.exists():
        return None

    try:
        with open(history_file, 'r') as f:
            return json.load(f)
    except (ValueError, AttributeError):
        return None


def get_version_from_reports(release):
    """Map release-X.Y to version from reports/{version}/ directory"""
    import re
    from pathlib import Path

    # Extract X.Y from release-X.Y
    match = re.search(r'release-(\d+\.\d+)', release)
    if not match:
        return release.replace('release-', '')

    major_minor = match.group(1)

    # Find matching version directory in reports/ (e.g., reports/2.15.0/)
    reports_path = Path('reports')
    if not reports_path.exists():
        return major_minor

    # Find all matching version directories
    matching = []
    for item in reports_path.iterdir():
        if item.is_dir() and item.name.startswith(major_minor):
            # Verify it has json/ subdirectory (valid scan)
            if (item / 'json').exists():
                matching.append(item.name)

    if not matching:
        return major_minor

    # Sort by version and get latest (handle non-numeric like 2.15.0-rc1)
    def version_key(v):
        import re
        parts = []
        for part in v.split('.'):
            # Extract leading digits, default to 0
            match = re.match(r'^(\d+)', part)
            parts.append(int(match.group(1)) if match else 0)
        return parts

    matching.sort(key=version_key)
    return matching[-1]


def generate_tab_button(release, history=None, is_active=False):
    """Generate tab button HTML"""
    tab_id = release.replace('.', '').replace('-', '')  # release-2.17 -> release217

    # Try to get version from history first, fallback to reports dir
    if history and history.get('version'):
        display_name = history['version']
    else:
        display_name = get_version_from_reports(release)

    active_class = ' active' if is_active else ''
    return f'<button class="tab{active_class}" onclick="openTab(event, \'{tab_id}\')">{display_name}</button>'


def generate_component_cve_data_js(releases, cve_descriptions):
    """Generate JavaScript data mapping components to their CVEs"""
    component_data = {}

    for release, history in releases.items():
        tab_id = release.replace('.', '').replace('-', '')
        scans = history.get('scans', [])

        if not scans:
            continue

        latest_scan = scans[-1]
        cve_details = latest_scan.get('summary', {}).get('cve_details', [])

        # Group CVEs by component
        comp_cve_map = {}
        for detail in cve_details:
            component = detail.get('component')
            cve_id = detail.get('cve_id')
            severity = detail.get('severity', 'UNKNOWN')

            desc_data = cve_descriptions.get(cve_id, {})
            cvss_score = desc_data.get('cvss_score')
            description = desc_data.get('description', 'No description available')

            fixed_versions = detail.get('fixed_versions', [])
            if len(fixed_versions) == 0:
                fix_display = 'None'
            elif len(fixed_versions) == 1:
                fix_display = fixed_versions[0]
            else:
                fix_display = f"{fixed_versions[0]} (+{len(fixed_versions)-1} more)"

            if component not in comp_cve_map:
                comp_cve_map[component] = []

            comp_cve_map[component].append({
                'cve_id': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': description,
                'fix_display': fix_display
            })

        component_data[tab_id] = comp_cve_map

    return f"window.componentCVEData = {json.dumps(component_data)};"


def generate_release_tab_content(release, history, extras_metadata=None):
    """Generate tab content for a single release"""
    tab_id = release.replace('.', '').replace('-', '')  # release-2.17 -> release217

    scans = history.get('scans', [])

    if not scans:
        return f"""
    <div id="{tab_id}" class="tab-content">
        <div class="no-data">
            <h2>No data available for {release}</h2>
            <p>Run scans to populate trend data</p>
        </div>
    </div>"""

    latest_scan = scans[-1]
    latest_severity = latest_scan.get('summary', {}).get('by_severity', {})

    # Calculate trend
    trend_indicator = "—"
    trend_class = "trend"
    if len(scans) >= 2:
        latest_total = latest_severity.get('CRITICAL', 0) + latest_severity.get('HIGH', 0)
        previous_total = scans[-2].get('summary', {}).get('by_severity', {}).get('CRITICAL', 0) + \
                        scans[-2].get('summary', {}).get('by_severity', {}).get('HIGH', 0)
        delta = latest_total - previous_total
        if delta > 0:
            trend_indicator = f"+{delta}"
            trend_class = "trend worsening"
        elif delta < 0:
            trend_indicator = str(delta)
        else:
            trend_indicator = "0"

    # Get top components and separate internal vs external
    component_breakdown = latest_scan.get('summary', {}).get('component_breakdown', {})

    internal_components = []
    external_components = []

    for component, counts in component_breakdown.items():
        has_git_link = extras_metadata and component in extras_metadata and extras_metadata[component].get('git_url')

        if has_git_link:
            internal_components.append((component, counts))
        else:
            external_components.append((component, counts))

    # Sort both by total CVEs
    internal_components.sort(key=lambda x: x[1].get('total', 0), reverse=True)
    external_components.sort(key=lambda x: x[1].get('total', 0), reverse=True)

    internal_rows = []
    for i, (component, counts) in enumerate(internal_components):
        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        total = counts.get('total', 0)

        # Get git metadata and make clickable for CVE drill-down (use data attrs to avoid XSS)
        if extras_metadata and component in extras_metadata:
            meta = extras_metadata[component]
            if meta.get('commit_url'):
                commit_short = meta['git_revision'][:7] if meta.get('git_revision') else ''
                component_display = f'<span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span> <a href="{meta["commit_url"]}" target="_blank" style="text-decoration: none; color: #666; font-size: 0.85em;">({commit_short})</a>'
            else:
                component_display = f'<span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span>'
        else:
            component_display = f'<span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span>'

        # Hide rows beyond top 15 by default
        hidden_class = ' class="component-row-hidden"' if i >= 15 else ''

        internal_rows.append(f"""
                <tr{hidden_class} data-component="{component}" data-critical="{critical}" data-high="{high}" data-total="{total}">
                    <td>{component_display}</td>
                    <td style="text-align: center;"><span class="severity-badge severity-critical">{critical}</span></td>
                    <td style="text-align: center;"><span class="severity-badge severity-high">{high}</span></td>
                    <td style="text-align: center;">{total}</td>
                </tr>""")

    external_rows = []
    for i, (component, counts) in enumerate(external_components):
        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        total = counts.get('total', 0)

        # Hide rows beyond top 15 by default
        hidden_class = ' class="component-row-hidden"' if i >= 15 else ''

        external_rows.append(f"""
                <tr{hidden_class} data-component="{component}" data-critical="{critical}" data-high="{high}" data-total="{total}">
                    <td><span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span> <span style="color: #666; font-size: 0.85em;">(upstream)</span></td>
                    <td style="text-align: center;"><span class="severity-badge severity-critical">{critical}</span></td>
                    <td style="text-align: center;"><span class="severity-badge severity-high">{high}</span></td>
                    <td style="text-align: center;">{total}</td>
                </tr>""")

    return f"""
    <div id="{tab_id}" class="tab-content">
        <div class="summary-cards">
            <div class="summary-card critical">
                <h3>{latest_severity.get('CRITICAL', 0)}</h3>
                <p>CRITICAL (instances)</p>
            </div>
            <div class="summary-card high">
                <h3>{latest_severity.get('HIGH', 0)}</h3>
                <p>HIGH (instances)</p>
            </div>
            <div class="summary-card">
                <h3>{latest_scan.get('summary', {}).get('total_cves', 0)}</h3>
                <p>Unique CVEs</p>
                <p style="font-size: 0.8em; margin-top: 5px;">({latest_scan.get('summary', {}).get('total_matches', 0)} instances)</p>
            </div>
            <div class="summary-card {trend_class}">
                <h3>{trend_indicator}</h3>
                <p>Week-over-Week</p>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <h2>📈 CVE Trend Over Time</h2>
                <canvas id="trendChart-{tab_id}"></canvas>
            </div>
            <div class="chart-container">
                <h2>🔄 New vs Fixed CVEs</h2>
                <canvas id="deltaChart-{tab_id}"></canvas>
            </div>
        </div>

        {generate_blast_radius_section_multi(latest_scan, tab_id, extras_metadata.get('cve_descriptions', {}))}

        <h2 style="margin-bottom: 15px;">🏢 Internal Components (stolostron)</h2>
        <table class="component-table" id="componentTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortTable('{tab_id}', 0, 'string')">Component</th>
                    <th style="text-align: center;" onclick="sortTable('{tab_id}', 1, 'number')">CRITICAL</th>
                    <th style="text-align: center;" onclick="sortTable('{tab_id}', 2, 'number')">HIGH</th>
                    <th style="text-align: center;" onclick="sortTable('{tab_id}', 3, 'number')">Total CVEs</th>
                </tr>
            </thead>
            <tbody>
                {''.join(internal_rows)}
            </tbody>
        </table>
        {f'<button class="show-all-btn" onclick="toggleShowAll({chr(39)}{tab_id}{chr(39)}, {chr(39)}internal{chr(39)})">Show All Internal ({len(internal_components)} total)</button>' if len(internal_components) > 15 else ''}

        <h2 style="margin: 40px 0 15px 0;">🌐 External/Upstream Components</h2>
        <table class="component-table" id="externalTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortExternalTable('{tab_id}', 0, 'string')">Component</th>
                    <th style="text-align: center;" onclick="sortExternalTable('{tab_id}', 1, 'number')">CRITICAL</th>
                    <th style="text-align: center;" onclick="sortExternalTable('{tab_id}', 2, 'number')">HIGH</th>
                    <th style="text-align: center;" onclick="sortExternalTable('{tab_id}', 3, 'number')">Total CVEs</th>
                </tr>
            </thead>
            <tbody>
                {''.join(external_rows)}
            </tbody>
        </table>
        {f'<button class="show-all-btn" onclick="toggleShowAll({chr(39)}{tab_id}{chr(39)}, {chr(39)}external{chr(39)})">Show All External ({len(external_components)} total)</button>' if len(external_components) > 15 else ''}

        {generate_fixed_cves_section(latest_scan, tab_id)}
    </div>"""


def generate_blast_radius_section_multi(latest_scan, tab_id, cve_descriptions=None):
    """Generate blast radius analysis table for multi-release"""
    blast_radius_data = analyze_blast_radius(latest_scan, top_n=10)

    if not blast_radius_data:
        return ''

    if cve_descriptions is None:
        cve_descriptions = {}

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

        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        severity_value = severity_order.get(cve.get('severity', 'UNKNOWN'), 0)

        # Generate CVE link with tooltip
        cve_id = cve.get('cve_id', 'Unknown')

        # Get description and CVSS
        desc_data = cve_descriptions.get(cve_id, {})
        description = desc_data.get('description', 'No description available')
        cvss_score = desc_data.get('cvss_score')

        # Truncate description if too long
        if len(description) > 300:
            description = description[:297] + '...'

        # Build tooltip content
        tooltip_content = f'<div class="tooltip-title">{cve_id}</div>'
        if cvss_score:
            tooltip_content += f'<div class="tooltip-cvss">CVSS: {cvss_score} ({cve.get("severity", "UNKNOWN")})</div>'
        tooltip_content += f'<div>{description}</div>'

        # Generate link with tooltip wrapper
        if cve_id.startswith('CVE-'):
            base_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        elif cve_id.startswith('GO-'):
            base_link = f'https://pkg.go.dev/vuln/{cve_id}'
        else:
            base_link = '#'

        cve_link = f'''<div class="cve-tooltip">
            <a href="{base_link}" target="_blank" style="text-decoration: none; color: #0366d6;"><code>{cve_id}</code></a>
            <span class="tooltiptext">{tooltip_content}</span>
        </div>'''

        fix_available = cve.get('fix_display', 'None')

        # CVSS score display and color
        cvss_display = '—'
        cvss_color = '#666'
        cvss_value = 0
        if cvss_score:
            cvss_display = f'{cvss_score:.1f}'
            cvss_value = cvss_score
            if cvss_score >= 9.0:
                cvss_color = '#d73a49'  # Critical
            elif cvss_score >= 7.0:
                cvss_color = '#f66a0a'  # High
            elif cvss_score >= 4.0:
                cvss_color = '#e36209'  # Medium
            else:
                cvss_color = '#666'     # Low

        rows.append(f"""
                <tr data-cve="{cve_id}" data-severity="{severity_value}" data-count="{cve.get('component_count', 0)}" data-cvss="{cvss_value}" data-fixable="{1 if cve.get('fixable') else 0}">
                    <td>{cve_link}</td>
                    <td><span class="severity-badge {severity_class}">{cve.get('severity', 'UNKNOWN')}</span></td>
                    <td style="text-align: center;"><strong style="color: {cvss_color}; font-weight: 700;">{cvss_display}</strong></td>
                    <td style="text-align: center;"><strong style="color: #d73a49;">{cve.get('component_count', 0)}</strong></td>
                    <td style="font-size: 0.9em; color: #666;">{component_preview}</td>
                    <td style="text-align: center; color: {fixable_color}; font-size: 0.9em;">{fix_available}</td>
                    <td style="text-align: center; color: {fixable_color}; font-weight: bold;">{fixable}</td>
                </tr>""")

    return f"""
        <h2 style="margin: 40px 0 15px 0;">💥 Highest Blast Radius (CVEs affecting most components)</h2>
        <table class="component-table" id="blastTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortBlastTable('{tab_id}', 0, 'string')">CVE ID</th>
                    <th onclick="sortBlastTable('{tab_id}', 1, 'number')">Severity</th>
                    <th style="text-align: center;" onclick="sortBlastTable('{tab_id}', 2, 'number')">CVSS</th>
                    <th style="text-align: center;" onclick="sortBlastTable('{tab_id}', 3, 'number')">Components</th>
                    <th>Affected Components (preview)</th>
                    <th style="text-align: center;">Fix Available</th>
                    <th style="text-align: center;" onclick="sortBlastTable('{tab_id}', 6, 'number')">Fixable</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    """


def generate_fixed_cves_section(latest_scan, tab_id):
    """Generate fixed CVEs section for release tab"""
    fixed_cves = latest_scan.get('fixed_cves', [])

    if not fixed_cves:
        return ''

    rows = []
    for cve in fixed_cves[:20]:
        cve_id = cve.get('cve_id', 'Unknown')
        component = cve.get('component', 'unknown')
        rows.append(f"""
                <tr style="background: #dcffe4;" data-cve="{cve_id}" data-component="{component}">
                    <td><code>{cve_id}</code></td>
                    <td><code>{component}</code></td>
                </tr>""")

    return f"""
        <h2 style="margin: 40px 0 15px 0;">✅ Fixed CVEs (Resolved since last scan: {len(fixed_cves)})</h2>
        <table class="component-table" id="fixedTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortFixedTable('{tab_id}', 0)">CVE ID</th>
                    <th onclick="sortFixedTable('{tab_id}', 1)">Component</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    """


def generate_comparison_card(release, history):
    """Generate comparison card for a release"""
    scans = history.get('scans', [])

    if not scans:
        return f"""
        <div class="release-card">
            <h3>{release}</h3>
            <p style="color: #666;">No data available</p>
        </div>"""

    latest = scans[-1].get('summary', {}).get('by_severity', {})

    # Calculate trend
    trend = "—"
    if len(scans) >= 2:
        latest_total = latest.get('CRITICAL', 0) + latest.get('HIGH', 0)
        previous_total = scans[-2].get('summary', {}).get('by_severity', {}).get('CRITICAL', 0) + \
                        scans[-2].get('summary', {}).get('by_severity', {}).get('HIGH', 0)
        delta = latest_total - previous_total
        if delta > 0:
            trend = f"<span style='color: #d73a49;'>+{delta} ↑</span>"
        elif delta < 0:
            trend = f"<span style='color: #28a745;'>{delta} ↓</span>"
        else:
            trend = "<span style='color: #666;'>0 →</span>"

    return f"""
        <div class="release-card">
            <h3>{release}</h3>
            <div class="stat">
                <span>CRITICAL:</span>
                <strong style="color: #d73a49;">{latest.get('CRITICAL', 0)}</strong>
            </div>
            <div class="stat">
                <span>HIGH:</span>
                <strong style="color: #f66a0a;">{latest.get('HIGH', 0)}</strong>
            </div>
            <div class="stat">
                <span>Unique CVEs:</span>
                <strong>{scans[-1].get('summary', {}).get('total_cves', 0)}</strong>
            </div>
            <div class="stat">
                <span>Total instances:</span>
                <strong style="color: #666;">{scans[-1].get('summary', {}).get('total_matches', 0)}</strong>
            </div>
            <div class="stat">
                <span>Scans:</span>
                <strong>{len(scans)}</strong>
            </div>
            <div class="stat">
                <span>Trend:</span>
                {trend}
            </div>
        </div>"""


def generate_chart_data(release, history):
    """Generate JavaScript chart data for a release"""
    scans = history.get('scans', [])[-12:]  # Last 12 weeks
    tab_id = release.replace('.', '').replace('-', '')  # release-2.17 -> release217

    labels = [format_date_short(scan['timestamp']) for scan in scans]
    critical = [scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0) for scan in scans]
    high = [scan.get('summary', {}).get('by_severity', {}).get('HIGH', 0) for scan in scans]
    new_cves = [len(scan.get('new_cves', [])) for scan in scans]
    fixed_cves = [len(scan.get('fixed_cves', [])) for scan in scans]

    return f"""
        // {release} charts
        const trendCtx{tab_id} = document.getElementById('trendChart-{tab_id}');
        if (trendCtx{tab_id}) {{
            new Chart(trendCtx{tab_id}.getContext('2d'), {{
                type: 'line',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [
                        {{
                            label: 'CRITICAL',
                            data: {json.dumps(critical)},
                            borderColor: '#d73a49',
                            backgroundColor: 'rgba(215, 58, 73, 0.1)',
                            tension: 0.3,
                            fill: true
                        }},
                        {{
                            label: 'HIGH',
                            data: {json.dumps(high)},
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
                    plugins: {{ legend: {{ position: 'bottom' }} }},
                    scales: {{
                        x: {{
                            ticks: {{
                                callback: function(value, index) {{
                                    const timestamp = this.getLabelForValue(value);
                                    const date = new Date(timestamp);
                                    return (date.getMonth() + 1) + '/' + date.getDate() + ' ' +
                                           date.getHours().toString().padStart(2, '0') + ':' +
                                           date.getMinutes().toString().padStart(2, '0');
                                }}
                            }}
                        }},
                        y: {{ beginAtZero: true }}
                    }}
                }}
            }});
        }}

        const deltaCtx{tab_id} = document.getElementById('deltaChart-{tab_id}');
        if (deltaCtx{tab_id}) {{
            new Chart(deltaCtx{tab_id}.getContext('2d'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [
                        {{
                            label: 'New CVEs',
                            data: {json.dumps(new_cves)},
                            backgroundColor: '#d73a49'
                        }},
                        {{
                            label: 'Fixed CVEs',
                            data: {json.dumps(fixed_cves)},
                            backgroundColor: '#28a745'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{ legend: {{ position: 'bottom' }} }},
                    scales: {{
                        x: {{
                            ticks: {{
                                callback: function(value, index) {{
                                    const timestamp = this.getLabelForValue(value);
                                    const date = new Date(timestamp);
                                    return (date.getMonth() + 1) + '/' + date.getDate() + ' ' +
                                           date.getHours().toString().padStart(2, '0') + ':' +
                                           date.getMinutes().toString().padStart(2, '0');
                                }}
                            }}
                        }},
                        y: {{ beginAtZero: true }}
                    }}
                }}
            }});
        }}
    """


def main():
    parser = argparse.ArgumentParser(description='Generate multi-release CVE trend dashboard')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory (default: reports)')
    parser.add_argument('--output',
                       help='Output HTML file path (default: reports/trends/multi-release-dashboard.html)')

    args = parser.parse_args()

    trends_dir = Path(args.reports_dir) / 'trends'

    if not trends_dir.exists():
        console.print(f"[red]Trends directory not found: {trends_dir}[/red]")
        sys.exit(1)

    # Find all history files
    history_files = list(trends_dir.glob('release-*-history.json'))

    if not history_files:
        console.print("[yellow]No release history files found[/yellow]")
        sys.exit(0)

    console.print(f"[cyan]Found {len(history_files)} releases[/cyan]")

    # Load git metadata from extras
    extras_metadata = load_extras_metadata()

    # Load CVE descriptions
    cve_descriptions = load_cve_descriptions(args.reports_dir)
    extras_metadata['cve_descriptions'] = cve_descriptions

    # Load all histories
    releases = {}
    for history_file in sorted(history_files):
        release = history_file.stem.replace('-history', '')
        history = load_release_history(trends_dir, release)
        if history:
            releases[release] = history
            console.print(f"  • {release}: {len(history.get('scans', []))} scans")

    if not releases:
        console.print("[yellow]No valid history data found[/yellow]")
        sys.exit(0)

    # Generate HTML components
    tab_buttons = '\n'.join([generate_tab_button(rel, hist) for rel, hist in sorted(releases.items())])
    tab_contents = '\n'.join([generate_release_tab_content(rel, hist, extras_metadata) for rel, hist in sorted(releases.items())])
    comparison_cards = '\n'.join([generate_comparison_card(rel, hist) for rel, hist in sorted(releases.items())])

    # Generate component CVE data for drill-down
    component_cve_data_js = generate_component_cve_data_js(releases, cve_descriptions)

    # Generate comparison chart data
    compare_labels = []
    compare_critical = []
    compare_high = []

    for release in sorted(releases.keys()):
        history = releases[release]
        scans = history.get('scans', [])
        if scans:
            compare_labels.append(release)
            latest = scans[-1].get('summary', {}).get('by_severity', {})
            compare_critical.append(latest.get('CRITICAL', 0))
            compare_high.append(latest.get('HIGH', 0))

    compare_data_js = f"const compareData = {json.dumps({'labels': compare_labels, 'critical': compare_critical, 'high': compare_high})};"

    # Generate individual chart scripts
    individual_charts = '\n'.join([generate_chart_data(rel, hist) for rel, hist in sorted(releases.items())])

    # Generate final HTML
    html = HTML_TEMPLATE.format(
        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        tab_buttons=tab_buttons,
        tab_contents=tab_contents,
        comparison_cards=comparison_cards,
        chart_data_js=compare_data_js,
        component_cve_data_js=component_cve_data_js,
        individual_charts_js=individual_charts
    )

    # Determine output path
    output_path = args.output
    if not output_path:
        output_path = trends_dir / 'multi-release-dashboard.html'
    else:
        output_path = Path(output_path)

    # Write HTML
    try:
        with open(output_path, 'w') as f:
            f.write(html)
        console.print(f"[green]✓ Multi-release dashboard generated: {output_path}[/green]")
    except (OSError, PermissionError) as e:
        console.print(f"[red]Error writing HTML: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
