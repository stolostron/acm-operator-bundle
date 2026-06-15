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
        :root {{
            --bg-primary: #f5f5f5;
            --bg-secondary: #ffffff;
            --text-primary: #333;
            --text-secondary: #666;
            --border-color: #e1e4e8;
            --hover-bg: #f6f8fa;
            --shadow: rgba(0,0,0,0.1);
        }}

        [data-theme="dark"] {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --hover-bg: #21262d;
            --shadow: rgba(0,0,0,0.3);
        }}

        a {{
            color: #0366d6;
        }}

        [data-theme="dark"] a {{
            color: #58a6ff;
        }}

        a:visited {{
            color: #0366d6;
        }}

        [data-theme="dark"] a:visited {{
            color: #58a6ff;
        }}

        a code {{
            color: inherit;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background 0.3s, color 0.3s;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
            position: relative;
        }}

        .theme-toggle {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.2);
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            color: white;
            font-size: 0.9em;
            transition: background 0.3s;
        }}

        .theme-toggle:hover {{
            background: rgba(255,255,255,0.3);
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
            background: var(--bg-secondary);
            padding: 0;
            display: flex;
            border-bottom: 2px solid var(--border-color);
            overflow-x: auto;
        }}

        .tab {{
            padding: 15px 25px;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 1em;
            color: var(--text-secondary);
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
            white-space: nowrap;
        }}

        .tab:hover {{
            background: var(--hover-bg);
            color: var(--text-primary);
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
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 2px 8px var(--shadow);
        }}

        .chart-container h2 {{
            font-size: 1.2em;
            margin-bottom: 15px;
            color: var(--text-primary);
        }}

        canvas {{
            max-height: 300px;
        }}

        .component-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 8px var(--shadow);
        }}

        .component-table th,
        .component-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .component-table th {{
            background: var(--hover-bg);
            font-weight: 600;
            color: var(--text-primary);
            cursor: pointer;
            user-select: none;
            position: relative;
            padding-right: 25px;
        }}

        .component-table th:hover {{
            background: var(--border-color);
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
            background: var(--hover-bg);
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

        .severity-medium {{
            background: #fb8500;
            color: white;
        }}

        .severity-low {{
            background: #ffd60a;
            color: #333;
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

        select {{
            outline: none;
        }}

        select:hover {{
            border-color: #0366d6 !important;
        }}

        select:focus {{
            border-color: #0366d6 !important;
            box-shadow: 0 0 0 3px rgba(3, 102, 214, 0.1);
        }}

        .component-row-hidden {{
            display: none;
        }}

        .cve-tooltip {{
            position: relative;
            cursor: help;
            display: inline-block;
        }}

        .cve-tooltip .tooltiptext {{
            visibility: hidden;
            width: 400px;
            background-color: #24292e;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 15px;
            position: fixed;
            z-index: 10000;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.9em;
            line-height: 1.5;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            pointer-events: none;
        }}

        [data-theme="dark"] .cve-tooltip .tooltiptext {{
            background-color: #21262d;
            color: #c9d1d9;
            box-shadow: 0 4px 12px rgba(0,0,0,0.6);
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
            background-color: var(--bg-secondary);
            margin: 5% auto;
            padding: 0;
            border: 1px solid var(--border-color);
            width: 90%;
            max-width: 1000px;
            border-radius: 8px;
            box-shadow: 0 4px 20px var(--shadow);
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

        [data-theme="dark"] .component-link {{
            color: #58a6ff;
        }}

        [data-theme="dark"] .component-link:hover {{
            color: #79b8ff;
        }}

        .commit-link {{
            color: #8b949e;
            text-decoration: none;
        }}

        .commit-link:hover {{
            color: #0366d6;
            text-decoration: underline;
        }}

        [data-theme="dark"] .commit-link {{
            color: #8b949e;
        }}

        [data-theme="dark"] .commit-link:hover {{
            color: #58a6ff;
            text-decoration: underline;
        }}

        .cve-blast-link {{
            text-decoration: none;
            color: #0366d6;
        }}

        .cve-blast-link:hover {{
            text-decoration: underline;
        }}

        [data-theme="dark"] .cve-blast-link {{
            color: #58a6ff;
        }}

        [data-theme="dark"] .cve-blast-link:hover {{
            text-decoration: underline;
        }}

        .section-header {{
            cursor: pointer;
            user-select: none;
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 40px 0 15px 0;
        }}

        .section-header:hover {{
            color: #0366d6;
        }}

        .section-header::before {{
            content: '▼';
            font-size: 0.8em;
            transition: transform 0.3s;
        }}

        .section-header.collapsed::before {{
            transform: rotate(-90deg);
        }}

        .collapsible-content {{
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}

        .collapsible-content.collapsed {{
            max-height: 0 !important;
        }}

        /* Compare All tab specific styles */
        .comparison-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .release-card {{
            background: var(--bg-secondary);
            padding: 16px;
            border-radius: 6px;
            box-shadow: 0 2px 8px var(--shadow);
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .release-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 6px 16px var(--shadow);
        }}

        .release-card h3 {{
            font-size: 1.3em;
            margin-bottom: 15px;
            color: var(--text-primary);
        }}

        .release-card .stat {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
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
        <button class="theme-toggle" onclick="toggleTheme()" id="themeToggle">🌙 Dark Mode</button>
        <h1>🔒 ACM CVE Trend Dashboard</h1>
        <p class="meta">Multi-Release Analysis | Updated: {timestamp}</p>
    </div>

    <div class="tabs">
        <button class="tab active" onclick="openTab(event, 'compare-all')">📊 Compare All</button>
        {tab_buttons}
    </div>

    <div id="compare-all" class="tab-content active">
        <div style="margin-bottom: 20px; display: flex; gap: 10px; align-items: center;">
            <button id="filterCritical" class="show-all-btn" onclick="filterComparison('CRITICAL')" style="background: #d73a49; opacity: 0.5;">CRITICAL</button>
            <button id="filterHigh" class="show-all-btn" onclick="filterComparison('HIGH')" style="background: #f66a0a; opacity: 0.5;">HIGH</button>
            <button id="filterMedium" class="show-all-btn" onclick="filterComparison('MEDIUM')" style="background: #fb8500; opacity: 0.5;">MEDIUM</button>
            <button id="filterLow" class="show-all-btn" onclick="filterComparison('LOW')" style="background: #ffd60a; opacity: 0.5;">LOW</button>
            <button id="filterAll" class="show-all-btn" onclick="filterComparison(null)" style="background: #0366d6; border: 2px solid #0366d6;">All</button>
            <div style="flex: 1;"></div>
            <button class="show-all-btn" onclick="toggleView('cards')" id="viewCards" style="background: #0366d6; border: 2px solid #0366d6;">📊 Cards</button>
            <button class="show-all-btn" onclick="toggleView('chart')" id="viewChart" style="background: #666; opacity: 0.5;">📈 Chart</button>
        </div>

        <h2 id="comparison-header" class="section-header" onclick="toggleSection('comparison')" style="margin-bottom: 20px; font-size: 1.8em;">📊 Release Overview</h2>
        <div id="comparison-content" class="collapsible-content" style="max-height: none;">
            <div id="cardsView" class="comparison-grid">
                {comparison_cards}
            </div>
            <div id="chartView" class="chart-container" style="display: none;">
                <canvas id="compareChart"></canvas>
            </div>
        </div>

        {cross_release_table}
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

        // Theme toggle
        function toggleTheme() {{
            const html = document.documentElement;
            const btn = document.getElementById('themeToggle');
            const currentTheme = html.getAttribute('data-theme');

            if (currentTheme === 'dark') {{
                html.removeAttribute('data-theme');
                btn.textContent = '🌙 Dark Mode';
                localStorage.setItem('theme', 'light');
            }} else {{
                html.setAttribute('data-theme', 'dark');
                btn.textContent = '☀️ Light Mode';
                localStorage.setItem('theme', 'dark');
            }}
        }}

        // Load saved theme
        (function() {{
            const savedTheme = localStorage.getItem('theme');
            const html = document.documentElement;
            const btn = document.getElementById('themeToggle');

            if (savedTheme === 'dark') {{
                html.setAttribute('data-theme', 'dark');
                btn.textContent = '☀️ Light Mode';
            }}
        }})();

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

            // Save active tab to localStorage
            localStorage.setItem('activeTab', tabName);
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

            // Separate visible and hidden rows (based on current filter/squad)
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            const hiddenRows = rows.filter(row => row.style.display === 'none');

            // Sort only visible rows
            visibleRows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    // Use data attributes for numeric sorting
                    const dataAttr = ['component', 'critical', 'high', 'medium', 'low', 'total'][columnIndex];
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

            // Re-append visible rows first, then hidden rows (to maintain filter)
            visibleRows.forEach(row => tbody.appendChild(row));
            hiddenRows.forEach(row => tbody.appendChild(row));

            // Reset to page 1 after sort
            const resetFn = window['currentPageInternal' + tabId];
            if (typeof resetFn !== 'undefined') window['currentPageInternal' + tabId] = 1;
            const applyFn = window['applyPageInternal' + tabId];
            if (applyFn) applyFn();
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

            // Separate visible and hidden rows (based on current filter/squad)
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            const hiddenRows = rows.filter(row => row.style.display === 'none');

            // Sort only visible rows
            visibleRows.sort((a, b) => {{
                let aVal, bVal;

                if (type === 'number') {{
                    const dataAttr = ['component', 'critical', 'high', 'medium', 'low', 'total'][columnIndex];
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

            // Re-append visible rows first, then hidden rows
            visibleRows.forEach(row => tbody.appendChild(row));
            hiddenRows.forEach(row => tbody.appendChild(row));

            // Reset to page 1 after sort
            const resetFn = window['currentPageExternal' + tabId];
            if (typeof resetFn !== 'undefined') window['currentPageExternal' + tabId] = 1;
            const applyFn = window['applyPageExternal' + tabId];
            if (applyFn) applyFn();
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
                    const dataAttr = ['cve', 'severity', 'cvss', 'count', '', '', 'fixable', 'days'][columnIndex];
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

        function sortUnfixableTable(tabId, columnIndex, type) {{
            const table = document.getElementById('unfixableTable-' + tabId);
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
                    const dataAttr = ['cve', 'severity', 'cvss', 'component', '', 'days'][columnIndex];
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

        function openTabById(tabId) {{
            // Find button with matching onclick containing tabId
            const buttons = document.querySelectorAll('.tab');
            for (const btn of buttons) {{
                const onclick = btn.getAttribute('onclick');
                if (onclick && onclick.includes(tabId)) {{
                    btn.click();
                    break;
                }}
            }}
        }}

        function toggleView(view) {{
            const cardsView = document.getElementById('cardsView');
            const chartView = document.getElementById('chartView');
            const cardsBtn = document.getElementById('viewCards');
            const chartBtn = document.getElementById('viewChart');

            if (view === 'cards') {{
                cardsView.style.display = 'grid';
                chartView.style.display = 'none';
                cardsBtn.style.opacity = '1';
                cardsBtn.style.border = '2px solid #0366d6';
                chartBtn.style.opacity = '0.5';
                chartBtn.style.border = 'none';
            }} else {{
                cardsView.style.display = 'none';
                chartView.style.display = 'block';
                chartBtn.style.opacity = '1';
                chartBtn.style.border = '2px solid #0366d6';
                cardsBtn.style.opacity = '0.5';
                cardsBtn.style.border = 'none';
            }}
        }}

        function filterComparison(severity) {{
            const cards = document.querySelectorAll('.release-card');
            const crossTable = document.getElementById('crossReleaseTable');

            // Update button states
            const critBtn = document.getElementById('filterCritical');
            const highBtn = document.getElementById('filterHigh');
            const medBtn = document.getElementById('filterMedium');
            const lowBtn = document.getElementById('filterLow');
            const allBtn = document.getElementById('filterAll');

            [critBtn, highBtn, medBtn, lowBtn, allBtn].forEach(btn => {{
                btn.style.opacity = '0.5';
                btn.style.border = 'none';
            }});

            const severityColors = {{
                'CRITICAL': '#d73a49',
                'HIGH': '#f66a0a',
                'MEDIUM': '#fb8500',
                'LOW': '#ffd60a'
            }};

            // Remove existing no-data message
            const existingMsg = document.getElementById('noDataMessage');
            if (existingMsg) existingMsg.remove();

            if (!severity) {{
                allBtn.style.opacity = '1';
                allBtn.style.border = '2px solid #0366d6';
                cards.forEach(card => card.style.display = '');
                if (crossTable) {{
                    crossTable.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
                }}
            }} else {{
                const btnMap = {{
                    'CRITICAL': critBtn,
                    'HIGH': highBtn,
                    'MEDIUM': medBtn,
                    'LOW': lowBtn
                }};
                const activeBtn = btnMap[severity];
                activeBtn.style.opacity = '1';
                activeBtn.style.border = '2px solid ' + severityColors[severity];

                let visibleCount = 0;
                cards.forEach(card => {{
                    const count = parseInt(card.dataset[severity.toLowerCase()] || 0);
                    if (count > 0) {{
                        card.style.display = '';
                        visibleCount++;
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});

                // Show "no data" message if no cards visible
                if (visibleCount === 0) {{
                    const cardsView = document.getElementById('cardsView');
                    if (cardsView) {{
                        const msg = document.createElement('div');
                        msg.id = 'noDataMessage';
                        msg.style.cssText = 'text-align: center; padding: 60px 20px; color: var(--text-secondary); font-size: 1.1em;';
                        msg.innerHTML = '<div style="font-size: 3em; margin-bottom: 10px;">📭</div>No releases with ' + severity + ' CVEs';
                        cardsView.appendChild(msg);
                    }}
                }}

                if (crossTable) {{
                    crossTable.querySelectorAll('tbody tr').forEach(row => {{
                        const rowSeverity = row.querySelector('.severity-badge')?.textContent.trim();
                        row.style.display = rowSeverity === severity ? '' : 'none';
                    }});
                }}
            }}
        }}

        function sortCrossReleaseTable(columnIndex, type) {{
            const table = document.getElementById('crossReleaseTable');
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
                    const dataAttr = ['cve', 'severity', 'releases', '', ''][columnIndex];
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

            // Get active filter for this tab
            const activeFilter = window['activeSeverityFilter_' + tabId] || null;

            // Filter data if severity filter active
            const filteredData = activeFilter
                ? componentData.filter(cve => cve.severity === activeFilter)
                : componentData;

            // Build CVE table with sorting
            const tableId = 'modalTable-' + component.replace(/[^a-zA-Z0-9]/g, '_');
            const filterNote = activeFilter ? ` (filtered to ${{activeFilter}} only)` : '';
            let html = `
                <p><strong>${{filteredData.length}} CVEs found${{filterNote}}</strong></p>
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

            filteredData.forEach(cve => {{
                const cvssDisplay = cve.cvss_score ? cve.cvss_score.toFixed(1) : '—';
                const cvssValue = cve.cvss_score || 0;
                const cvssColor = cve.cvss_score >= 9 ? '#d73a49' : cve.cvss_score >= 7 ? '#f66a0a' : '#666';
                const severityClass = 'severity-' + cve.severity.toLowerCase();
                const severityValue = severityOrder[cve.severity] || 0;
                const description = cve.description.substring(0, 150) + (cve.description.length > 150 ? '...' : '');

                let cveLink;
                if (cve.cve_id.startsWith('CVE-')) {{
                    cveLink = `<a href="https://access.redhat.com/security/cve/${{cve.cve_id}}" target="_blank"><code>${{cve.cve_id}}</code></a> <a href="https://nvd.nist.gov/vuln/detail/${{cve.cve_id}}" target="_blank" style="font-size: 0.8em; color: var(--text-secondary);">(NVD)</a>`;
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

        // Position fixed tooltip relative to trigger element
        document.addEventListener('mouseover', function(e) {{
            const trigger = e.target.closest('.cve-tooltip');
            if (trigger) {{
                const tooltipEl = trigger.querySelector('.tooltiptext');
                if (tooltipEl) {{
                    const rect = trigger.getBoundingClientRect();
                    const tooltipWidth = 400;
                    const gap = 10;

                    // Default: right side
                    let left = rect.right + gap;
                    let top = rect.top;

                    // Flip to left if would overflow viewport
                    if (left + tooltipWidth > window.innerWidth) {{
                        left = rect.left - tooltipWidth - gap;
                    }}

                    // Keep in viewport bounds
                    if (left < 0) left = gap;
                    if (top < 0) top = gap;

                    tooltipEl.style.left = left + 'px';
                    tooltipEl.style.top = top + 'px';
                }}
            }}
        }});

        // Attach click handlers to component links (prevents XSS from inline onclick)
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.component-link').forEach(link => {{
                link.addEventListener('click', function() {{
                    const component = this.getAttribute('data-component');
                    const tabId = this.getAttribute('data-tab');
                    showComponentCVEs(component, tabId);
                }});
            }});

            // Inject unique counts into component tables
            if (window.componentUniqueCounts) {{
                Object.keys(window.componentUniqueCounts).forEach(tabId => {{
                    const counts = window.componentUniqueCounts[tabId];
                    Object.keys(counts).forEach(component => {{
                        const uniqueCount = counts[component];
                        const elemId = 'total-' + tabId + '-' + component.replace(/\\//g, '-');
                        const elem = document.getElementById(elemId);
                        if (elem) {{
                            const totalCount = parseInt(elem.textContent);
                            if (uniqueCount < totalCount) {{
                                elem.innerHTML = totalCount + ' <span style="color: #666; font-size: 0.85em;">(' + uniqueCount + ' unique)</span>';
                            }}
                        }}
                    }});
                }});
            }}

            // Apply initial page size to all tables
            document.querySelectorAll('[id^="cvesTable-"]').forEach(table => {{
                const tabId = table.id.replace('cvesTable-', '');

                // Apply CVE pagination
                const applyPageCVE = window['applyPageCVE' + tabId];
                if (applyPageCVE) applyPageCVE();

                // Apply component pagination
                const applyPageInternal = window['applyPageInternal' + tabId];
                if (applyPageInternal) applyPageInternal();

                const applyPageExternal = window['applyPageExternal' + tabId];
                if (applyPageExternal) applyPageExternal();
            }});

            // Restore active tab from localStorage
            const savedTab = localStorage.getItem('activeTab');
            if (savedTab) {{
                const tabBtn = document.querySelector(`[onclick*="'${{savedTab}}'"]`);
                if (tabBtn) {{
                    tabBtn.click();
                }}
            }}
        }});

        function toggleSection(sectionId) {{
            const header = document.getElementById(sectionId + '-header');
            const content = document.getElementById(sectionId + '-content');

            if (!header || !content) return;

            if (content.classList.contains('collapsed')) {{
                content.classList.remove('collapsed');
                header.classList.remove('collapsed');
                content.style.maxHeight = content.scrollHeight + 'px';
            }} else {{
                content.classList.add('collapsed');
                header.classList.add('collapsed');
                content.style.maxHeight = '0';
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
    """Generate JavaScript data mapping components to their CVEs and unique counts"""
    component_data = {}
    component_unique_counts = {}

    for release, history in releases.items():
        tab_id = release.replace('.', '').replace('-', '')
        scans = history.get('scans', [])

        if not scans:
            continue

        latest_scan = scans[-1]
        cve_details = latest_scan.get('summary', {}).get('cve_details', [])

        # Group CVEs by component, dedupe by cve_id
        comp_cve_map = {}
        for detail in cve_details:
            component = detail.get('component')
            cve_id = detail.get('cve_id')
            severity = detail.get('severity', 'UNKNOWN')

            if component not in comp_cve_map:
                comp_cve_map[component] = {}

            # Skip if already seen this CVE for this component
            if cve_id in comp_cve_map[component]:
                continue

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

            comp_cve_map[component][cve_id] = {
                'cve_id': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'description': description,
                'fix_display': fix_display
            }

        # Store unique counts for each component
        unique_counts = {comp: len(cves) for comp, cves in comp_cve_map.items()}
        component_unique_counts[tab_id] = unique_counts

        # Convert dict to list for JSON
        for component in comp_cve_map:
            comp_cve_map[component] = list(comp_cve_map[component].values())

        component_data[tab_id] = comp_cve_map

    return f"window.componentCVEData = {json.dumps(component_data)};\nwindow.componentUniqueCounts = {json.dumps(component_unique_counts)};"


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
        medium = counts.get('MEDIUM', 0)
        low = counts.get('LOW', 0)
        total = counts.get('total', 0)

        # Get git metadata and make clickable for CVE drill-down (use data attrs to avoid XSS)
        if extras_metadata and component in extras_metadata:
            meta = extras_metadata[component]
            display_name = meta.get('image_name', component)

            # Build rich tooltip
            tooltip_parts = [f'<div class="tooltip-title">{component}</div>']
            if meta.get('squad'):
                tooltip_parts.append(f'<div><strong>Squad:</strong> {meta["squad"]}</div>')
            if meta.get('jira_component'):
                tooltip_parts.append(f'<div><strong>JIRA:</strong> {meta["jira_component"]}</div>')
            if meta.get('repository'):
                repo_short = meta['repository'].replace('https://github.com/', '')
                tooltip_parts.append(f'<div><strong>Repo:</strong> {repo_short}</div>')

            tooltip_content = ''.join(tooltip_parts)
            name_html = f'<div class="cve-tooltip"><span class="component-link" data-component="{component}" data-tab="{tab_id}">{display_name}</span><span class="tooltiptext">{tooltip_content}</span></div>'

            if meta.get('commit_url'):
                commit_short = meta['git_revision'][:7] if meta.get('git_revision') else ''
                component_display = f'{name_html} <a href="{meta["commit_url"]}" target="_blank" class="commit-link" style="font-size: 0.85em;">({commit_short})</a>'
            else:
                component_display = name_html
        else:
            component_display = f'<span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span>'

        # Hide rows beyond top 15 by default
        hidden_class = ' class="component-row-hidden"' if i >= 15 else ''

        squad = ''
        if extras_metadata and component in extras_metadata:
            squad = extras_metadata[component].get('squad', '')

        internal_rows.append(f"""
                <tr{hidden_class} data-component="{component}" data-squad="{squad}" data-critical="{critical}" data-high="{high}" data-medium="{medium}" data-low="{low}" data-total="{total}">
                    <td>{component_display}</td>
                    <td class="col-critical" style="text-align: center;"><span class="severity-badge severity-critical">{critical}</span></td>
                    <td class="col-high" style="text-align: center;"><span class="severity-badge severity-high">{high}</span></td>
                    <td class="col-medium" style="text-align: center;"><span class="severity-badge severity-medium">{medium}</span></td>
                    <td class="col-low" style="text-align: center;"><span class="severity-badge severity-low">{low}</span></td>
                    <td style="text-align: center;"><span id="total-{tab_id}-{component.replace('/', '-')}">{total}</span></td>
                </tr>""")

    external_rows = []
    for i, (component, counts) in enumerate(external_components):
        critical = counts.get('CRITICAL', 0)
        high = counts.get('HIGH', 0)
        medium = counts.get('MEDIUM', 0)
        low = counts.get('LOW', 0)
        total = counts.get('total', 0)

        squad = ''
        if extras_metadata and component in extras_metadata:
            squad = extras_metadata[component].get('squad', '')

        # Check if component has metadata (image-name)
        if extras_metadata and component in extras_metadata:
            meta = extras_metadata[component]
            display_name = meta.get('image_name', component)

            # Build rich tooltip
            tooltip_parts = [f'<div class="tooltip-title">{component}</div>']
            if meta.get('squad'):
                tooltip_parts.append(f'<div><strong>Squad:</strong> {meta["squad"]}</div>')
            if meta.get('jira_component'):
                tooltip_parts.append(f'<div><strong>JIRA:</strong> {meta["jira_component"]}</div>')
            if meta.get('repository'):
                repo_short = meta['repository'].replace('https://github.com/', '')
                tooltip_parts.append(f'<div><strong>Repo:</strong> {repo_short}</div>')

            tooltip_content = ''.join(tooltip_parts)
            name_html = f'<div class="cve-tooltip"><span class="component-link" data-component="{component}" data-tab="{tab_id}">{display_name}</span><span class="tooltiptext">{tooltip_content}</span></div>'

            component_display = f'{name_html} <span style="color: #666; font-size: 0.85em;">(upstream)</span>'
        else:
            component_display = f'<span class="component-link" data-component="{component}" data-tab="{tab_id}">{component}</span> <span style="color: #666; font-size: 0.85em;">(upstream)</span>'

        # Hide rows beyond top 15 by default
        hidden_class = ' class="component-row-hidden"' if i >= 15 else ''

        external_rows.append(f"""
                <tr{hidden_class} data-component="{component}" data-squad="{squad}" data-critical="{critical}" data-high="{high}" data-medium="{medium}" data-low="{low}" data-total="{total}">
                    <td>{component_display}</td>
                    <td class="col-critical" style="text-align: center;"><span class="severity-badge severity-critical">{critical}</span></td>
                    <td class="col-high" style="text-align: center;"><span class="severity-badge severity-high">{high}</span></td>
                    <td class="col-medium" style="text-align: center;"><span class="severity-badge severity-medium">{medium}</span></td>
                    <td class="col-low" style="text-align: center;"><span class="severity-badge severity-low">{low}</span></td>
                    <td style="text-align: center;"><span id="total-{tab_id}-{component.replace('/', '-')}">{total}</span></td>
                </tr>""")

    # Get all squads from registry (not just current release components)
    all_squads = extras_metadata.get('all_squads', set()) if extras_metadata else set()
    squad_options = ''.join([f'<option value="{squad}">{squad}</option>' for squad in sorted(all_squads)])

    # Calculate fixable and unfixable counts
    cve_details = latest_scan.get('summary', {}).get('cve_details', [])
    fixable_cves = set()
    unfixable_cves = set()
    for detail in cve_details:
        cve_id = detail.get('cve_id')
        if detail.get('fixed_versions'):
            fixable_cves.add(cve_id)
        else:
            unfixable_cves.add(cve_id)
    fixable_count = len(fixable_cves)
    unfixable_count = len(unfixable_cves)

    total_cves = latest_scan.get('summary', {}).get('total_cves', 0)
    critical_count = latest_severity.get('CRITICAL', 0)
    high_count = latest_severity.get('HIGH', 0)
    medium_count = latest_severity.get('MEDIUM', 0)
    low_count = latest_severity.get('LOW', 0)

    return f"""
    <div id="{tab_id}" class="tab-content">
        <div style="background: var(--bg-secondary); padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px var(--shadow); margin-bottom: 30px; display: flex; align-items: center; gap: 40px;">
            <div style="flex: 0 0 200px;">
                <canvas id="severityDonut-{tab_id}" width="200" height="200"></canvas>
            </div>
            <div style="flex: 1;">
                <h2 style="font-size: 1.5em; margin-bottom: 15px; color: var(--text-primary);">Grype has detected <strong>{total_cves}</strong> vulnerabilities.</h2>
                <p style="font-size: 1.2em; margin-bottom: 20px; color: var(--text-primary);">Patches available for <strong style="color: #28a745;">{fixable_count}</strong> vulnerabilities. <strong style="color: #dc3545;">{unfixable_count}</strong> have no upstream fix.</p>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; font-size: 0.95em; color: var(--text-primary);">
                    <div><span style="color: #d73a49;">⚠</span> <strong>{critical_count}</strong> Critical-level vulnerabilities.</div>
                    <div><span style="color: #f66a0a;">⚠</span> <strong>{high_count}</strong> High-level vulnerabilities.</div>
                    <div><span style="color: #e36209;">⚠</span> <strong>{medium_count}</strong> Medium-level vulnerabilities.</div>
                    <div><span style="color: var(--text-secondary);">⚠</span> <strong>{low_count}</strong> Low-level vulnerabilities.</div>
                </div>
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

        {generate_combined_cve_table(latest_scan, tab_id, extras_metadata.get('cve_descriptions', {}), history)}

        <hr style="margin: 40px 0 30px 0; border: none; border-top: 2px solid var(--border-color);">

        <div style="margin-bottom: 20px; display: flex; gap: 25px; align-items: center; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 10px; flex: 1; min-width: 250px;">
                <label for="componentSearch-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Search:</label>
                <input type="text" id="componentSearch-{tab_id}" placeholder="Component name..." oninput="searchComponents{tab_id}(this.value)" style="flex: 1; padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; transition: border-color 0.2s;">
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <label for="squadFilter-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Squad:</label>
                <select id="squadFilter-{tab_id}" onchange="filterBySquad{tab_id}(this.value)" style="padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; cursor: pointer; transition: border-color 0.2s; min-width: 180px;">
                    <option value="">All Squads</option>
                    {squad_options}
                </select>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
                <label for="componentFilter-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Component:</label>
                <select id="componentFilter-{tab_id}" onchange="filterByComponent{tab_id}(this.value)" style="padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; cursor: pointer; transition: border-color 0.2s; min-width: 200px;">
                    <option value="">All Components</option>
                </select>
            </div>
        </div>

        <h2 id="internal-{tab_id}-header" class="section-header" onclick="toggleSection('internal-{tab_id}')">🏢 Internal Components (stolostron)</h2>
        <div id="internal-{tab_id}-content" class="collapsible-content" style="max-height: none;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <div id="internalCounter-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em;"></div>
            <div id="internalPagination-{tab_id}" style="display: flex; gap: 10px; align-items: center;">
                <button onclick="prevPageInternal{tab_id}()" id="internalPrevBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">← Previous</button>
                <span id="internalPageInfo-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em; min-width: 80px; text-align: center;"></span>
                <button onclick="nextPageInternal{tab_id}()" id="internalNextBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">Next →</button>
            </div>
        </div>
        <table class="component-table" id="componentTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortTable('{tab_id}', 0, 'string')" style="min-width: 300px;">Component</th>
                    <th class="col-critical" style="text-align: center;" onclick="sortTable('{tab_id}', 1, 'number')">CRITICAL</th>
                    <th class="col-high" style="text-align: center;" onclick="sortTable('{tab_id}', 2, 'number')">HIGH</th>
                    <th class="col-medium" style="text-align: center;" onclick="sortTable('{tab_id}', 3, 'number')">MEDIUM</th>
                    <th class="col-low" style="text-align: center;" onclick="sortTable('{tab_id}', 4, 'number')">LOW</th>
                    <th style="text-align: center;" onclick="sortTable('{tab_id}', 5, 'number')">Total CVEs</th>
                </tr>
            </thead>
            <tbody>
                {''.join(internal_rows)}
            </tbody>
        </table>
        </div>

        <h2 id="external-{tab_id}-header" class="section-header" onclick="toggleSection('external-{tab_id}')">🌐 External/Upstream Components</h2>
        <div id="external-{tab_id}-content" class="collapsible-content" style="max-height: none;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <div id="externalCounter-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em;"></div>
            <div id="externalPagination-{tab_id}" style="display: flex; gap: 10px; align-items: center;">
                <button onclick="prevPageExternal{tab_id}()" id="externalPrevBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">← Previous</button>
                <span id="externalPageInfo-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em; min-width: 80px; text-align: center;"></span>
                <button onclick="nextPageExternal{tab_id}()" id="externalNextBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">Next →</button>
            </div>
        </div>
        <table class="component-table" id="externalTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortExternalTable('{tab_id}', 0, 'string')" style="min-width: 300px;">Component</th>
                    <th class="col-critical" style="text-align: center;" onclick="sortExternalTable('{tab_id}', 1, 'number')">CRITICAL</th>
                    <th class="col-high" style="text-align: center;" onclick="sortExternalTable('{tab_id}', 2, 'number')">HIGH</th>
                    <th class="col-medium" style="text-align: center;" onclick="sortExternalTable('{tab_id}', 3, 'number')">MEDIUM</th>
                    <th class="col-low" style="text-align: center;" onclick="sortExternalTable('{tab_id}', 4, 'number')">LOW</th>
                    <th style="text-align: center;" onclick="sortExternalTable('{tab_id}', 5, 'number')">Total CVEs</th>
                </tr>
            </thead>
            <tbody>
                {''.join(external_rows)}
            </tbody>
        </table>
        </div>

        {generate_fixed_cves_section(latest_scan, tab_id)}
    </div>"""


def generate_combined_cve_table(latest_scan, tab_id, cve_descriptions=None, history=None):
    """Generate combined CVE table with fixable filter"""
    blast_radius_data = analyze_blast_radius(latest_scan, top_n=1000)  # Get all CVEs

    if not blast_radius_data:
        return ''

    if cve_descriptions is None:
        cve_descriptions = {}

    # Get first_seen tracking
    cve_first_seen = history.get('cve_first_seen', {}) if history else {}

    rows = []
    for i, cve in enumerate(blast_radius_data):
        severity_class = 'severity-' + cve.get('severity', 'unknown').lower()
        fixable = cve.get('fixable', False)
        fixable_display = '✓' if fixable else '✗'
        fixable_color = '#28a745' if fixable else '#d73a49'
        fixable_class = 'fixable' if fixable else 'unfixable'

        # Hide rows beyond top 10 by default
        hidden_class = ' cve-row-hidden' if i >= 10 else ''

        # Get affected components
        components = cve.get('components', [])[:3]
        component_preview = ', '.join(components)
        if cve.get('component_count', 0) > 3:
            component_preview += f" +{cve.get('component_count') - 3} more"

        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        severity_value = severity_order.get(cve.get('severity', 'UNKNOWN'), 0)

        cve_id = cve.get('cve_id', 'Unknown')

        # Get description and CVSS
        desc_data = cve_descriptions.get(cve_id, {})
        description = desc_data.get('description', 'No description available')
        cvss_score = desc_data.get('cvss_score')

        if len(description) > 300:
            description = description[:297] + '...'

        tooltip_content = f'<div class="tooltip-title">{cve_id}</div>'
        if cvss_score:
            tooltip_content += f'<div class="tooltip-cvss">CVSS: {cvss_score} ({cve.get("severity", "UNKNOWN")})</div>'
        tooltip_content += f'<div>{description}</div>'

        if cve_id.startswith('CVE-'):
            base_link = f'https://access.redhat.com/security/cve/{cve_id}'
            nvd_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div> <a href="{nvd_link}" target="_blank" style="font-size: 0.8em; color: var(--text-secondary);">(NVD)</a>'''
        elif cve_id.startswith('GO-'):
            base_link = f'https://pkg.go.dev/vuln/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''
        else:
            cve_link = f'''<div class="cve-tooltip">
                <code>{cve_id}</code>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''

        cvss_display = '—'
        cvss_color = '#666'
        cvss_value = 0
        if cvss_score:
            cvss_display = f'{cvss_score:.1f}'
            cvss_value = cvss_score
            if cvss_score >= 9.0:
                cvss_color = '#d73a49'
            elif cvss_score >= 7.0:
                cvss_color = '#f66a0a'
            elif cvss_score >= 4.0:
                cvss_color = '#fb8500'
            else:
                cvss_color = '#ffd60a'

        # Calculate days open
        days_open = '—'
        days_open_value = 0
        days_open_color = '#666'
        cve_key = f"{cve_id}:{components[0] if components else 'unknown'}"
        first_seen_str = cve_first_seen.get(cve_key)
        if first_seen_str:
            from datetime import datetime, timezone
            ts = first_seen_str.rstrip('Z')
            if not ts.endswith('+00:00'):
                ts += '+00:00'
            first_seen = datetime.fromisoformat(ts)
            now = datetime.now(timezone.utc)
            days = (now - first_seen).days
            days_open = str(days)
            days_open_value = days
            if days > 90:
                days_open_color = '#d73a49'
            elif days > 30:
                days_open_color = '#f66a0a'
            elif days > 7:
                days_open_color = '#fb8500'

        rows.append(f'''
            <tr class="cve-row {fixable_class}{hidden_class}" data-cve="{cve_id}" data-severity="{severity_value}" data-cvss="{cvss_value}" data-component="{cve.get('component_count', 0)}" data-days="{days_open_value}" data-fixable="{1 if fixable else 0}">
                <td style="text-align: center; color: var(--text-secondary); font-size: 0.9em;">{i + 1}</td>
                <td>{cve_link}</td>
                <td style="text-align: center;"><span class="severity-badge {severity_class}">{cve.get('severity', 'UNKNOWN')}</span></td>
                <td style="text-align: center; color: {cvss_color}; font-weight: 600;">{cvss_display}</td>
                <td style="text-align: center;">{cve.get('component_count', 0)}</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{', '.join(cve.get('components', []))}">{component_preview}</td>
                <td style="text-align: center; color: {days_open_color}; font-weight: 600;">{days_open}</td>
                <td style="text-align: center; color: {fixable_color}; font-weight: 600; font-size: 1.2em;">{fixable_display}</td>
            </tr>''')

    return f'''
        <hr style="margin: 40px 0 30px 0; border: none; border-top: 2px solid var(--border-color);">

        <h2 id="cves-{tab_id}-header" class="section-header" onclick="toggleSection('cves-{tab_id}')">🔍 CVE Analysis</h2>
        <div id="cves-{tab_id}-content" class="collapsible-content" style="max-height: none;">
            <div style="margin-bottom: 20px; display: flex; gap: 25px; align-items: center; flex-wrap: wrap;">
                <div style="display: flex; align-items: center; gap: 10px; flex: 1; min-width: 250px;">
                    <label for="cveSearch-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Search:</label>
                    <input type="text" id="cveSearch-{tab_id}" placeholder="CVE ID or component name..." oninput="searchCVEs{tab_id}(this.value)" style="flex: 1; padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; transition: border-color 0.2s;">
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label for="fixableFilter-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Filter:</label>
                    <select id="fixableFilter-{tab_id}" onchange="filterByFixable{tab_id}(this.value)" style="padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; cursor: pointer; transition: border-color 0.2s; min-width: 160px;">
                        <option value="">All CVEs</option>
                        <option value="fixable">Fixable Only</option>
                        <option value="unfixable">Unfixable Only</option>
                    </select>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label for="pageSize-{tab_id}" style="font-weight: 600; font-size: 0.95em;">Show:</label>
                    <select id="pageSize-{tab_id}" onchange="updatePageSize{tab_id}(this.value)" style="padding: 10px 14px; border: 2px solid var(--border-color); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 0.95em; cursor: pointer; transition: border-color 0.2s; min-width: 100px;">
                        <option value="10" selected>10</option>
                        <option value="20">20</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="all">All</option>
                    </select>
                </div>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div id="cveCounter-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em;"></div>
                <div id="cvePagination-{tab_id}" style="display: flex; gap: 10px; align-items: center;">
                    <button onclick="prevPageCVE{tab_id}()" id="cvePrevBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">← Previous</button>
                    <span id="cvePageInfo-{tab_id}" style="color: var(--text-secondary); font-size: 0.9em; min-width: 80px; text-align: center;"></span>
                    <button onclick="nextPageCVE{tab_id}()" id="cveNextBtn-{tab_id}" style="padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-primary); cursor: pointer; font-size: 0.9em;">Next →</button>
                </div>
            </div>
            <table class="component-table" id="cvesTable-{tab_id}">
                <thead>
                    <tr>
                        <th style="text-align: center; width: 50px;">#</th>
                        <th onclick="sortCVETable{tab_id}(1, 'string')">CVE ID</th>
                        <th style="text-align: center;" onclick="sortCVETable{tab_id}(2, 'number')">Severity</th>
                        <th style="text-align: center;" onclick="sortCVETable{tab_id}(3, 'number')">CVSS</th>
                        <th style="text-align: center;" onclick="sortCVETable{tab_id}(4, 'number')">Components</th>
                        <th onclick="sortCVETable{tab_id}(5, 'string')">Affected</th>
                        <th style="text-align: center;" onclick="sortCVETable{tab_id}(6, 'number')">Days Open</th>
                        <th style="text-align: center;" onclick="sortCVETable{tab_id}(7, 'number')">Fixable</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
    '''


def generate_blast_radius_section_multi(latest_scan, tab_id, cve_descriptions=None, history=None):
    """Generate blast radius analysis table for multi-release"""
    blast_radius_data = analyze_blast_radius(latest_scan, top_n=10)

    if not blast_radius_data:
        return ''

    if cve_descriptions is None:
        cve_descriptions = {}

    # Get first_seen tracking
    cve_first_seen = history.get('cve_first_seen', {}) if history else {}

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
            base_link = f'https://access.redhat.com/security/cve/{cve_id}'
            nvd_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div> <a href="{nvd_link}" target="_blank" style="font-size: 0.8em; color: var(--text-secondary);">(NVD)</a>'''
        elif cve_id.startswith('GO-'):
            base_link = f'https://pkg.go.dev/vuln/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''
        else:
            cve_link = f'''<div class="cve-tooltip">
                <code>{cve_id}</code>
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

        # Calculate days open (use first component as reference)
        days_open = '—'
        days_open_value = 0
        days_open_color = 'var(--text-secondary)'
        if cve_first_seen and components:
            cve_key = f"{cve_id}:{components[0]}"
            first_seen_str = cve_first_seen.get(cve_key)
            if first_seen_str:
                from datetime import datetime, timezone
                # Handle both 'Z' and '+00:00' formats
                ts = first_seen_str.rstrip('Z')
                if not ts.endswith('+00:00'):
                    ts += '+00:00'
                first_seen = datetime.fromisoformat(ts)
                now = datetime.now(timezone.utc)
                days = (now - first_seen).days
                days_open = str(days)
                days_open_value = days
                if days > 90:
                    days_open_color = '#d73a49'  # Critical - open >90 days
                elif days > 30:
                    days_open_color = '#f66a0a'  # Warning - open >30 days

        rows.append(f"""
                <tr data-cve="{cve_id}" data-severity="{severity_value}" data-count="{cve.get('component_count', 0)}" data-cvss="{cvss_value}" data-fixable="{1 if cve.get('fixable') else 0}" data-days="{days_open_value}">
                    <td>{cve_link}</td>
                    <td><span class="severity-badge {severity_class}">{cve.get('severity', 'UNKNOWN')}</span></td>
                    <td style="text-align: center;"><strong style="color: {cvss_color}; font-weight: 700;">{cvss_display}</strong></td>
                    <td style="text-align: center;"><strong style="color: #d73a49;">{cve.get('component_count', 0)}</strong></td>
                    <td style="font-size: 0.9em; color: var(--text-secondary);">{component_preview}</td>
                    <td style="text-align: center; color: {fixable_color}; font-size: 0.9em;">{fix_available}</td>
                    <td style="text-align: center; color: {fixable_color}; font-weight: bold;">{fixable}</td>
                    <td style="text-align: center; color: {days_open_color}; font-weight: 600;">{days_open}</td>
                </tr>""")

    return f"""
        <div id="filterIndicator-{tab_id}" style="display: none; background: #0366d6; color: white; padding: 10px; border-radius: 6px; margin: 20px 0 15px 0; text-align: center; font-weight: 600;"></div>
        <h2 id="blast-{tab_id}-header" class="section-header" onclick="toggleSection('blast-{tab_id}')">💥 Highest Blast Radius (CVEs affecting most components)</h2>
        <div id="blast-{tab_id}-content" class="collapsible-content" style="max-height: none;">
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
                    <th style="text-align: center;" onclick="sortBlastTable('{tab_id}', 7, 'number')">Days Open</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        </div>
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
        <h2 id="fixed-{tab_id}-header" class="section-header" onclick="toggleSection('fixed-{tab_id}')">✅ Fixed CVEs (Resolved since last scan: {len(fixed_cves)})</h2>
        <div id="fixed-{tab_id}-content" class="collapsible-content" style="max-height: none;">
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
        </div>
    """


def generate_unfixable_cves_section(latest_scan, tab_id, cve_descriptions=None, history=None):
    """Generate unfixable CVEs section - vulnerabilities with no upstream patch"""
    cve_details = latest_scan.get('summary', {}).get('cve_details', [])

    if cve_descriptions is None:
        cve_descriptions = {}

    # Get first_seen tracking
    cve_first_seen = history.get('cve_first_seen', {}) if history else {}

    # Filter to unfixable only
    unfixable = [cve for cve in cve_details if not cve.get('fixed_versions')]

    if not unfixable:
        return ''

    # Sort by severity then component
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    unfixable.sort(key=lambda x: (
        -severity_order.get(x.get('severity', 'UNKNOWN'), 0),
        x.get('component', ''),
        x.get('cve_id', '')
    ))

    # Limit to top 50
    unfixable = unfixable[:50]

    rows = []
    for i, cve in enumerate(unfixable):
        cve_id = cve.get('cve_id', 'Unknown')
        severity = cve.get('severity', 'UNKNOWN')
        severity_class = 'severity-' + severity.lower()
        severity_value = severity_order.get(severity, 0)
        component = cve.get('component', 'unknown')
        package = cve.get('package', 'unknown')

        # Get description and CVSS
        desc_data = cve_descriptions.get(cve_id, {})
        description = desc_data.get('description', 'No description available')
        cvss_score = desc_data.get('cvss_score')

        # Truncate description
        if len(description) > 300:
            description = description[:297] + '...'

        # Build tooltip
        tooltip_content = f'<div class="tooltip-title">{cve_id}</div>'
        if cvss_score:
            tooltip_content += f'<div class="tooltip-cvss">CVSS: {cvss_score} ({severity})</div>'
        tooltip_content += f'<div>{description}</div>'

        # CVE link with tooltip
        if cve_id.startswith('CVE-'):
            base_link = f'https://access.redhat.com/security/cve/{cve_id}'
            nvd_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div> <a href="{nvd_link}" target="_blank" style="font-size: 0.8em; color: var(--text-secondary);">(NVD)</a>'''
        elif cve_id.startswith('GO-'):
            base_link = f'https://pkg.go.dev/vuln/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''
        else:
            cve_link = f'''<div class="cve-tooltip">
                <code>{cve_id}</code>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''

        # CVSS display
        cvss_display = '—'
        cvss_color = '#666'
        cvss_value = 0
        if cvss_score:
            cvss_display = f'{cvss_score:.1f}'
            cvss_value = cvss_score
            if cvss_score >= 9.0:
                cvss_color = '#d73a49'
            elif cvss_score >= 7.0:
                cvss_color = '#f66a0a'
            elif cvss_score >= 4.0:
                cvss_color = '#e36209'
            else:
                cvss_color = '#666'

        # Calculate days open
        days_open = '—'
        days_open_value = 0
        days_open_color = 'var(--text-secondary)'
        cve_key = f"{cve_id}:{component}"
        first_seen_str = cve_first_seen.get(cve_key)
        if first_seen_str:
            from datetime import datetime, timezone
            # Handle both 'Z' and '+00:00' formats
            ts = first_seen_str.rstrip('Z')
            if not ts.endswith('+00:00'):
                ts += '+00:00'
            first_seen = datetime.fromisoformat(ts)
            now = datetime.now(timezone.utc)
            days = (now - first_seen).days
            days_open = str(days)
            days_open_value = days
            if days > 90:
                days_open_color = '#d73a49'
            elif days > 30:
                days_open_color = '#f66a0a'

        # Hide rows beyond 15 by default
        hidden_class = ' class="component-row-hidden"' if i >= 15 else ''

        rows.append(f"""
                <tr{hidden_class} data-cve="{cve_id}" data-severity="{severity_value}" data-cvss="{cvss_value}" data-component="{component}" data-days="{days_open_value}">
                    <td>{cve_link}</td>
                    <td><span class="severity-badge {severity_class}">{severity}</span></td>
                    <td style="text-align: center;"><strong style="color: {cvss_color}; font-weight: 700;">{cvss_display}</strong></td>
                    <td style="font-size: 0.9em;"><code>{component}</code></td>
                    <td style="font-size: 0.85em; color: var(--text-secondary);">{package}</td>
                    <td style="text-align: center; color: {days_open_color}; font-weight: 600;">{days_open}</td>
                </tr>""")

    return f"""
        <h2 id="unfixable-{tab_id}-header" class="section-header" onclick="toggleSection('unfixable-{tab_id}')">🚫 Unfixable CVEs (No upstream patch available: {len(unfixable)})</h2>
        <div id="unfixable-{tab_id}-content" class="collapsible-content" style="max-height: none;">
        <p style="color: var(--text-secondary); margin-bottom: 15px;">These vulnerabilities have no fix available from upstream. Consider mitigation strategies or risk acceptance.</p>
        <table class="component-table" id="unfixableTable-{tab_id}">
            <thead>
                <tr>
                    <th onclick="sortUnfixableTable('{tab_id}', 0, 'string')">CVE ID</th>
                    <th onclick="sortUnfixableTable('{tab_id}', 1, 'number')">Severity</th>
                    <th style="text-align: center;" onclick="sortUnfixableTable('{tab_id}', 2, 'number')">CVSS</th>
                    <th onclick="sortUnfixableTable('{tab_id}', 3, 'string')">Component</th>
                    <th>Package</th>
                    <th style="text-align: center;" onclick="sortUnfixableTable('{tab_id}', 5, 'number')">Days Open</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        {f'<button class="show-all-btn" onclick="toggleShowAll({chr(39)}{tab_id}{chr(39)}, {chr(39)}unfixable{chr(39)})">Show All Unfixable ({len(unfixable)} total)</button>' if len(unfixable) > 15 else ''}
        </div>
    """


def generate_cross_release_cve_table(releases, cve_descriptions=None):
    """Generate table of CVEs appearing across multiple releases"""
    if cve_descriptions is None:
        cve_descriptions = {}

    # Track CVE occurrences across releases
    cve_tracker = {}  # {cve_id: {releases: set(), severity: str, fixable: bool}}

    for release, history in releases.items():
        scans = history.get('scans', [])
        if not scans:
            continue

        latest_scan = scans[-1]
        cve_details = latest_scan.get('summary', {}).get('cve_details', [])

        for cve in cve_details:
            cve_id = cve.get('cve_id')
            if cve_id not in cve_tracker:
                cve_tracker[cve_id] = {
                    'releases': set(),
                    'severity': cve.get('severity', 'UNKNOWN'),
                    'fixable': len(cve.get('fixed_versions', [])) > 0
                }
            cve_tracker[cve_id]['releases'].add(release)

    # Filter to CVEs in 3+ releases
    cross_release_cves = {
        cve_id: data for cve_id, data in cve_tracker.items()
        if len(data['releases']) >= 3
    }

    if not cross_release_cves:
        return ''

    # Sort by release count desc, then severity
    severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    sorted_cves = sorted(
        cross_release_cves.items(),
        key=lambda x: (-len(x[1]['releases']), -severity_order.get(x[1]['severity'], 0))
    )

    rows = []
    for cve_id, data in sorted_cves[:20]:  # Limit to top 20
        severity = data['severity']
        severity_class = 'severity-' + severity.lower()
        severity_value = severity_order.get(severity, 0)
        release_count = len(data['releases'])
        releases_list = ', '.join(sorted(data['releases']))
        fixable = '✓' if data['fixable'] else '✗'
        fixable_color = '#28a745' if data['fixable'] else '#666'

        # Get description
        desc_data = cve_descriptions.get(cve_id, {})
        description = desc_data.get('description', 'No description available')
        cvss_score = desc_data.get('cvss_score')

        if len(description) > 250:
            description = description[:247] + '...'

        # Build tooltip
        tooltip_content = f'<div class="tooltip-title">{cve_id}</div>'
        if cvss_score:
            tooltip_content += f'<div class="tooltip-cvss">CVSS: {cvss_score} ({severity})</div>'
        tooltip_content += f'<div>{description}</div>'

        # CVE link
        if cve_id.startswith('CVE-'):
            base_link = f'https://access.redhat.com/security/cve/{cve_id}'
            nvd_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div> <a href="{nvd_link}" target="_blank" style="font-size: 0.8em; color: var(--text-secondary);">(NVD)</a>'''
        elif cve_id.startswith('GO-'):
            base_link = f'https://pkg.go.dev/vuln/{cve_id}'
            cve_link = f'''<div class="cve-tooltip">
                <a href="{base_link}" target="_blank" class="cve-blast-link"><code>{cve_id}</code></a>
                <span class="tooltiptext">{tooltip_content}</span>
            </div>'''
        else:
            cve_link = f'<code>{cve_id}</code>'

        rows.append(f"""
                <tr data-cve="{cve_id}" data-severity="{severity_value}" data-releases="{release_count}">
                    <td>{cve_link}</td>
                    <td><span class="severity-badge {severity_class}">{severity}</span></td>
                    <td style="text-align: center;"><strong style="color: #d73a49;">{release_count}</strong></td>
                    <td style="font-size: 0.85em; color: var(--text-secondary);">{releases_list}</td>
                    <td style="text-align: center; color: {fixable_color}; font-weight: bold;">{fixable}</td>
                </tr>""")

    return f"""
        <h2 id="cross-release-header" class="section-header" onclick="toggleSection('cross-release')" style="margin-top: 30px;">🔗 Cross-Release CVEs (affecting 3+ releases)</h2>
        <div id="cross-release-content" class="collapsible-content" style="max-height: none;">
            <p style="color: var(--text-secondary); margin-bottom: 15px;">Fix these CVEs once to improve security across multiple releases.</p>
            <table class="component-table" id="crossReleaseTable">
                <thead>
                    <tr>
                        <th onclick="sortCrossReleaseTable(0, 'string')">CVE ID</th>
                        <th onclick="sortCrossReleaseTable(1, 'number')">Severity</th>
                        <th style="text-align: center;" onclick="sortCrossReleaseTable(2, 'number')">Releases Affected</th>
                        <th>Release List</th>
                        <th style="text-align: center;" onclick="sortCrossReleaseTable(4, 'number')">Fixable</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
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

    # Calculate health score: critical×4 + high×3 + unfixable×2
    critical_count = latest.get('CRITICAL', 0)
    high_count = latest.get('HIGH', 0)
    medium_count = latest.get('MEDIUM', 0)
    low_count = latest.get('LOW', 0)

    # Count unfixable CVEs
    cve_details = scans[-1].get('summary', {}).get('cve_details', [])
    unfixable_count = sum(1 for cve in cve_details if not cve.get('fixed_versions'))

    health_score = (critical_count * 4) + (high_count * 3) + (unfixable_count * 2)

    # Color code health score
    if health_score > 100:
        score_color = '#d73a49'  # Critical
        score_label = 'Critical'
    elif health_score > 50:
        score_color = '#f66a0a'  # High
        score_label = 'High Risk'
    elif health_score > 20:
        score_color = '#e36209'  # Medium
        score_label = 'Medium Risk'
    else:
        score_color = '#28a745'  # Low
        score_label = 'Low Risk'

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

    tab_id = release.replace('.', '').replace('-', '')
    total_cves = scans[-1].get('summary', {}).get('total_cves', 0)
    critical_pct = (critical_count / max(total_cves, 1)) * 100 if total_cves > 0 else 0
    high_pct = (high_count / max(total_cves, 1)) * 100 if total_cves > 0 else 0

    return (health_score, f"""
        <div class="release-card" data-critical="{critical_count}" data-high="{high_count}" data-medium="{medium_count}" data-low="{low_count}"
             data-tab="{tab_id}" onclick="openTabById('{tab_id}')"
             style="border-left: 4px solid {score_color}; cursor: pointer; transition: all 0.2s ease;">
            <h3 style="margin: 0 0 12px 0; font-size: 1.1em;">{release}</h3>
            <div style="margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                    <span style="font-size: 0.85em; font-weight: 600; color: #d73a49;">CRIT</span>
                    <strong style="color: #d73a49; font-size: 1.1em;">{critical_count}</strong>
                </div>
                <div style="background: var(--border-color); height: 6px; border-radius: 3px; overflow: hidden;">
                    <div style="background: #d73a49; height: 100%; width: {critical_pct:.1f}%;"></div>
                </div>
            </div>
            <div style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 3px;">
                    <span style="font-size: 0.85em; font-weight: 600; color: #f66a0a;">HIGH</span>
                    <strong style="color: #f66a0a; font-size: 1.1em;">{high_count}</strong>
                </div>
                <div style="background: var(--border-color); height: 6px; border-radius: 3px; overflow: hidden;">
                    <div style="background: #f66a0a; height: 100%; width: {high_pct:.1f}%;"></div>
                </div>
            </div>
            <div style="border-top: 1px solid var(--border-color); padding-top: 8px; font-size: 0.8em; color: var(--text-secondary); display: grid; grid-template-columns: 1fr 1fr; gap: 6px;">
                <div><span>Unique:</span> <strong>{scans[-1].get('summary', {}).get('total_cves', 0)}</strong></div>
                <div><span>Total:</span> <strong>{scans[-1].get('summary', {}).get('total_matches', 0)}</strong></div>
                <div><span>Scans:</span> <strong>{len(scans)}</strong></div>
                <div><span>Trend:</span> {trend}</div>
            </div>
        </div>""")


def generate_chart_data(release, history):
    """Generate JavaScript chart data for a release"""
    scans = history.get('scans', [])[-12:]  # Last 12 weeks
    tab_id = release.replace('.', '').replace('-', '')  # release-2.17 -> release217

    labels = [format_date_short(scan['timestamp']) for scan in scans]
    critical = [scan.get('summary', {}).get('by_severity', {}).get('CRITICAL', 0) for scan in scans]
    high = [scan.get('summary', {}).get('by_severity', {}).get('HIGH', 0) for scan in scans]
    new_cves = [len(scan.get('new_cves', [])) for scan in scans]
    fixed_cves = [len(scan.get('fixed_cves', [])) for scan in scans]

    # Get latest severity for donut chart
    latest_severity = scans[-1].get('summary', {}).get('by_severity', {}) if scans else {}

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

        // Severity donut chart with click filtering
        const donutCtx{tab_id} = document.getElementById('severityDonut-{tab_id}');
        if (donutCtx{tab_id}) {{
            let activeSeverity{tab_id} = null;
            const baseColors = ['#d73a49', '#f66a0a', '#e36209', '#999'];
            const dimmedColors = ['rgba(215, 58, 73, 0.2)', 'rgba(246, 106, 10, 0.2)', 'rgba(227, 98, 9, 0.2)', 'rgba(153, 153, 153, 0.2)'];
            const getBorderColor = () => document.documentElement.getAttribute('data-theme') === 'dark' ? '#fff' : '#000';

            const donutChart{tab_id} = new Chart(donutCtx{tab_id}.getContext('2d'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: {json.dumps([latest_severity.get('CRITICAL', 0), latest_severity.get('HIGH', 0), latest_severity.get('MEDIUM', 0), latest_severity.get('LOW', 0)])},
                        backgroundColor: baseColors.slice(),
                        borderColor: ['transparent', 'transparent', 'transparent', 'transparent'],
                        borderWidth: [0, 0, 0, 0]
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{ display: false }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percent = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return label + ': ' + value + ' (' + percent + '%)';
                                }}
                            }}
                        }}
                    }},
                    onClick: (event, elements) => {{
                        if (elements.length > 0) {{
                            const index = elements[0].index;
                            const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][index];

                            // Toggle filter
                            if (activeSeverity{tab_id} === severity) {{
                                activeSeverity{tab_id} = null;
                                filterBySeverity{tab_id}(null);
                                // Reset colors and borders
                                donutChart{tab_id}.data.datasets[0].backgroundColor = baseColors.slice();
                                donutChart{tab_id}.data.datasets[0].borderColor = ['transparent', 'transparent', 'transparent', 'transparent'];
                                donutChart{tab_id}.data.datasets[0].borderWidth = [0, 0, 0, 0];
                            }} else {{
                                activeSeverity{tab_id} = severity;
                                filterBySeverity{tab_id}(severity);
                                // Highlight selected, dim others
                                const newColors = dimmedColors.slice();
                                newColors[index] = baseColors[index];
                                donutChart{tab_id}.data.datasets[0].backgroundColor = newColors;

                                // Add border to selected segment
                                const newBorders = ['transparent', 'transparent', 'transparent', 'transparent'];
                                const newWidths = [0, 0, 0, 0];
                                newBorders[index] = getBorderColor();
                                newWidths[index] = 4;
                                donutChart{tab_id}.data.datasets[0].borderColor = newBorders;
                                donutChart{tab_id}.data.datasets[0].borderWidth = newWidths;
                            }}
                            donutChart{tab_id}.update();
                        }}
                    }}
                }}
            }});

            // Filter function for blast radius and component tables
            window.filterBySeverity{tab_id} = function(severity) {{
                // Track active filter state globally
                window['activeSeverityFilter_{tab_id}'] = severity;

                const blastTable = document.getElementById('blastTable-{tab_id}');
                const unfixableTable = document.getElementById('unfixableTable-{tab_id}');
                const componentTable = document.getElementById('componentTable-{tab_id}');
                const externalTable = document.getElementById('externalTable-{tab_id}');
                const indicator = document.getElementById('filterIndicator-{tab_id}');

                // Column visibility control
                const toggleColumn = (table, columnClass, visible) => {{
                    if (!table) return;
                    table.querySelectorAll(columnClass).forEach(el => {{
                        el.style.display = visible ? '' : 'none';
                    }});
                }};

                if (!severity) {{
                    // Clear all filters and show all columns
                    if (blastTable) {{
                        blastTable.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
                    }}
                    if (unfixableTable) {{
                        unfixableTable.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
                    }}
                    if (componentTable) {{
                        componentTable.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
                        toggleColumn(componentTable, '.col-critical', true);
                        toggleColumn(componentTable, '.col-high', true);
                        toggleColumn(componentTable, '.col-medium', true);
                        toggleColumn(componentTable, '.col-low', true);
                    }}
                    if (externalTable) {{
                        externalTable.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
                        toggleColumn(externalTable, '.col-critical', true);
                        toggleColumn(externalTable, '.col-high', true);
                        toggleColumn(externalTable, '.col-medium', true);
                        toggleColumn(externalTable, '.col-low', true);
                    }}
                    if (indicator) indicator.style.display = 'none';
                }} else {{
                    // Filter blast radius table by severity badge
                    if (blastTable) {{
                        blastTable.querySelectorAll('tbody tr').forEach(row => {{
                            const rowSeverity = row.querySelector('.severity-badge')?.textContent.trim();
                            row.style.display = rowSeverity === severity ? '' : 'none';
                        }});
                    }}

                    // Filter unfixable table by severity badge
                    if (unfixableTable) {{
                        unfixableTable.querySelectorAll('tbody tr').forEach(row => {{
                            const rowSeverity = row.querySelector('.severity-badge')?.textContent.trim();
                            row.style.display = rowSeverity === severity ? '' : 'none';
                        }});
                    }}

                    // Filter component tables - hide components and columns
                    [componentTable, externalTable].forEach(table => {{
                        if (!table) return;

                        // Hide non-selected severity columns
                        toggleColumn(table, '.col-critical', severity === 'CRITICAL');
                        toggleColumn(table, '.col-high', severity === 'HIGH');
                        toggleColumn(table, '.col-medium', severity === 'MEDIUM');
                        toggleColumn(table, '.col-low', severity === 'LOW');

                        // Hide rows with 0 of selected severity
                        table.querySelectorAll('tbody tr').forEach(row => {{
                            const count = parseInt(row.dataset[severity.toLowerCase()] || 0);
                            row.style.display = count > 0 ? '' : 'none';
                        }});
                    }});

                    if (indicator) {{
                        indicator.textContent = `Showing ${{severity}} vulnerabilities only (click chart again to clear)`;
                        indicator.style.display = 'block';
                    }}
                }}
            }};

            // Update CVE counter
            // Track current page for CVE table
            let currentPageCVE{tab_id} = 1;

            window.updateCVECounter{tab_id} = function(matchingRowCount) {{
                const cvesTable = document.getElementById('cvesTable-{tab_id}');
                const counter = document.getElementById('cveCounter-{tab_id}');
                const pageInfo = document.getElementById('cvePageInfo-{tab_id}');
                const prevBtn = document.getElementById('cvePrevBtn-{tab_id}');
                const nextBtn = document.getElementById('cveNextBtn-{tab_id}');
                const pagination = document.getElementById('cvePagination-{tab_id}');

                if (!cvesTable || !counter) return;

                const allRows = cvesTable.querySelectorAll('tbody tr');
                const visibleRows = Array.from(allRows).filter(row => row.style.display !== 'none');
                const pageSizeSelect = document.getElementById('pageSize-{tab_id}');
                const pageSize = pageSizeSelect ? pageSizeSelect.value : '10';

                // Use passed matchingRowCount if available, otherwise count all
                const totalMatching = matchingRowCount !== undefined ? matchingRowCount : allRows.length;
                counter.textContent = `Showing ${{visibleRows.length}} of ${{totalMatching}} CVEs`;

                // Update pagination controls
                if (pageSize === 'all' || totalMatching === 0) {{
                    if (pagination) pagination.style.display = 'none';
                }} else {{
                    if (pagination) pagination.style.display = 'flex';
                    const limit = parseInt(pageSize);
                    const totalPages = Math.ceil(totalMatching / limit);

                    if (pageInfo) pageInfo.textContent = `Page ${{currentPageCVE{tab_id}}} of ${{totalPages}}`;
                    if (prevBtn) prevBtn.disabled = currentPageCVE{tab_id} <= 1;
                    if (nextBtn) nextBtn.disabled = currentPageCVE{tab_id} >= totalPages;
                }}
            }};

            window.applyPageCVE{tab_id} = function() {{
                const cvesTable = document.getElementById('cvesTable-{tab_id}');
                if (!cvesTable) return;

                const pageSizeSelect = document.getElementById('pageSize-{tab_id}');
                const pageSize = pageSizeSelect ? pageSizeSelect.value : '10';
                const filterSelect = document.getElementById('fixableFilter-{tab_id}');
                const activeFilter = filterSelect ? filterSelect.value : '';

                // Count matching rows first
                let matchingCount = 0;
                cvesTable.querySelectorAll('tbody tr').forEach(row => {{
                    const fixable = row.dataset.fixable === '1';
                    let passesFilter = true;
                    if (activeFilter === 'fixable' && !fixable) passesFilter = false;
                    if (activeFilter === 'unfixable' && fixable) passesFilter = false;
                    if (passesFilter) matchingCount++;
                }});

                if (pageSize === 'all') {{
                    cvesTable.querySelectorAll('tbody tr').forEach(row => {{
                        const fixable = row.dataset.fixable === '1';
                        let passesFilter = true;
                        if (activeFilter === 'fixable' && !fixable) passesFilter = false;
                        if (activeFilter === 'unfixable' && fixable) passesFilter = false;
                        row.style.display = passesFilter ? 'table-row' : 'none';
                    }});
                    updateCVECounter{tab_id}(matchingCount);
                    return;
                }}

                const limit = parseInt(pageSize);
                const startIdx = (currentPageCVE{tab_id} - 1) * limit;
                const endIdx = startIdx + limit;

                let visibleIndex = 0;
                cvesTable.querySelectorAll('tbody tr').forEach(row => {{
                    const fixable = row.dataset.fixable === '1';
                    let passesFilter = true;
                    if (activeFilter === 'fixable' && !fixable) passesFilter = false;
                    if (activeFilter === 'unfixable' && fixable) passesFilter = false;

                    if (passesFilter) {{
                        // Update # column
                        const numberCell = row.cells[0];
                        if (numberCell) numberCell.textContent = visibleIndex + 1;

                        if (visibleIndex >= startIdx && visibleIndex < endIdx) {{
                            row.style.display = 'table-row';
                        }} else {{
                            row.style.display = 'none';
                        }}
                        visibleIndex++;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                updateCVECounter{tab_id}(matchingCount);
            }};

            window.prevPageCVE{tab_id} = function() {{
                if (currentPageCVE{tab_id} > 1) {{
                    currentPageCVE{tab_id}--;
                    applyPageCVE{tab_id}();
                }}
            }};

            window.nextPageCVE{tab_id} = function() {{
                const cvesTable = document.getElementById('cvesTable-{tab_id}');
                const pageSizeSelect = document.getElementById('pageSize-{tab_id}');
                const pageSize = pageSizeSelect ? pageSizeSelect.value : '10';
                const limit = parseInt(pageSize);

                const visibleRows = Array.from(cvesTable.querySelectorAll('tbody tr')).filter(row => {{
                    const filterSelect = document.getElementById('fixableFilter-{tab_id}');
                    const activeFilter = filterSelect ? filterSelect.value : '';
                    const fixable = row.dataset.fixable === '1';

                    if (activeFilter === 'fixable' && !fixable) return false;
                    if (activeFilter === 'unfixable' && fixable) return false;
                    return true;
                }});

                const totalPages = Math.ceil(visibleRows.length / limit);
                if (currentPageCVE{tab_id} < totalPages) {{
                    currentPageCVE{tab_id}++;
                    applyPageCVE{tab_id}();
                }}
            }};

            // Search CVEs
            window.searchCVEs{tab_id} = function(query) {{
                const cvesTable = document.getElementById('cvesTable-{tab_id}');
                if (!cvesTable) return;

                const searchTerm = query.toLowerCase().trim();

                if (!searchTerm) {{
                    // Search cleared, re-apply pagination
                    currentPageCVE{tab_id} = 1;
                    applyPageCVE{tab_id}();
                    return;
                }}

                // Disable pagination during search - show all matching results
                const pagination = document.getElementById('cvePagination-{tab_id}');
                if (pagination) pagination.style.display = 'none';

                let matchIndex = 0;
                cvesTable.querySelectorAll('tbody tr').forEach(row => {{
                    const cveId = row.dataset.cve.toLowerCase();
                    const affectedCell = row.cells[5]; // Affected components column (adjusted for # column)
                    const affected = affectedCell ? affectedCell.textContent.toLowerCase() : '';

                    if (cveId.includes(searchTerm) || affected.includes(searchTerm)) {{
                        matchIndex++;
                        const numberCell = row.cells[0];
                        if (numberCell) numberCell.textContent = matchIndex;
                        row.style.display = 'table-row';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                updateCVECounter{tab_id}();
            }};

            // Update page size
            window.updatePageSize{tab_id} = function(size) {{
                currentPageCVE{tab_id} = 1;  // Reset to page 1 when page size changes
                applyPageCVE{tab_id}();
            }};

            // CVE fixable filter function
            window.filterByFixable{tab_id} = function(filter) {{
                currentPageCVE{tab_id} = 1;  // Reset to page 1 when filter changes
                applyPageCVE{tab_id}();
            }};

            // CVE table sort function
            window.sortCVETable{tab_id} = function(columnIndex, type) {{
                const table = document.getElementById('cvesTable-{tab_id}');
                if (!table) return;

                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const header = table.querySelectorAll('th')[columnIndex];

                const currentSort = header.classList.contains('sort-asc') ? 'asc' :
                                   header.classList.contains('sort-desc') ? 'desc' : 'none';
                const newSort = currentSort === 'asc' ? 'desc' : 'asc';

                table.querySelectorAll('th').forEach(th => {{
                    th.classList.remove('sort-asc', 'sort-desc');
                }});

                header.classList.add('sort-' + newSort);

                rows.sort((a, b) => {{
                    let aVal, bVal;

                    if (type === 'number') {{
                        const dataAttr = ['', 'cve', 'severity', 'cvss', 'component', '', 'days', 'fixable'][columnIndex];
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

                // Re-apply search or filter/page size
                const searchInput = document.getElementById('cveSearch-{tab_id}');
                const searchTerm = searchInput ? searchInput.value.trim() : '';

                if (searchTerm) {{
                    // Re-apply search
                    searchCVEs{tab_id}(searchTerm);
                }} else {{
                    // Re-apply current filter/page size to maintain visibility
                    const filterSelect = document.getElementById('fixableFilter-{tab_id}');
                    const activeFilter = filterSelect ? filterSelect.value : '';
                    filterByFixable{tab_id}(activeFilter);
                }}
            }};

            // Track current pages for component tables
            let currentPageInternal{tab_id} = 1;
            let currentPageExternal{tab_id} = 1;
            const COMPONENT_PAGE_SIZE = 15;

            // Update component counters
            window.updateComponentCounters{tab_id} = function() {{
                const componentTable = document.getElementById('componentTable-{tab_id}');
                const externalTable = document.getElementById('externalTable-{tab_id}');
                const internalCounter = document.getElementById('internalCounter-{tab_id}');
                const externalCounter = document.getElementById('externalCounter-{tab_id}');
                const internalPageInfo = document.getElementById('internalPageInfo-{tab_id}');
                const externalPageInfo = document.getElementById('externalPageInfo-{tab_id}');
                const internalPrevBtn = document.getElementById('internalPrevBtn-{tab_id}');
                const internalNextBtn = document.getElementById('internalNextBtn-{tab_id}');
                const externalPrevBtn = document.getElementById('externalPrevBtn-{tab_id}');
                const externalNextBtn = document.getElementById('externalNextBtn-{tab_id}');

                if (componentTable && internalCounter) {{
                    const allRows = componentTable.querySelectorAll('tbody tr');
                    const visibleRows = Array.from(allRows).filter(row => row.style.display !== 'none');
                    internalCounter.textContent = `Showing ${{visibleRows.length}} of ${{allRows.length}} internal components`;

                    const totalPages = Math.ceil(allRows.length / COMPONENT_PAGE_SIZE);
                    if (internalPageInfo) internalPageInfo.textContent = `Page ${{currentPageInternal{tab_id}}} of ${{totalPages}}`;
                    if (internalPrevBtn) internalPrevBtn.disabled = currentPageInternal{tab_id} <= 1;
                    if (internalNextBtn) internalNextBtn.disabled = currentPageInternal{tab_id} >= totalPages;
                }}

                if (externalTable && externalCounter) {{
                    const allRows = externalTable.querySelectorAll('tbody tr');
                    const visibleRows = Array.from(allRows).filter(row => row.style.display !== 'none');
                    externalCounter.textContent = `Showing ${{visibleRows.length}} of ${{allRows.length}} external components`;

                    const totalPages = Math.ceil(allRows.length / COMPONENT_PAGE_SIZE);
                    if (externalPageInfo) externalPageInfo.textContent = `Page ${{currentPageExternal{tab_id}}} of ${{totalPages}}`;
                    if (externalPrevBtn) externalPrevBtn.disabled = currentPageExternal{tab_id} <= 1;
                    if (externalNextBtn) externalNextBtn.disabled = currentPageExternal{tab_id} >= totalPages;
                }}
            }};

            window.applyPageInternal{tab_id} = function() {{
                const table = document.getElementById('componentTable-{tab_id}');
                if (!table) return;

                const squadFilter = document.getElementById('squadFilter-{tab_id}');
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                const activeSquad = squadFilter ? squadFilter.value : '';
                const activeComponent = componentFilter ? componentFilter.value : '';

                const rows = Array.from(table.querySelectorAll('tbody tr'));

                // First pass: determine which rows match current filters
                const matchingRows = rows.filter(row => {{
                    let matches = true;
                    if (activeSquad && row.dataset.squad !== activeSquad) matches = false;
                    if (activeComponent && row.dataset.component !== activeComponent) matches = false;
                    return matches;
                }});

                // Paginate only matching rows
                const startIdx = (currentPageInternal{tab_id} - 1) * COMPONENT_PAGE_SIZE;
                const endIdx = startIdx + COMPONENT_PAGE_SIZE;
                let visibleIndex = 0;

                rows.forEach(row => {{
                    const isMatching = matchingRows.includes(row);

                    if (!isMatching) {{
                        // Doesn't match filter - hide
                        row.style.display = 'none';
                        row.classList.add('component-row-hidden');
                    }} else {{
                        // Matches filter - apply pagination
                        if (visibleIndex >= startIdx && visibleIndex < endIdx) {{
                            row.style.display = '';
                            row.classList.remove('component-row-hidden');
                        }} else {{
                            row.style.display = 'none';
                            row.classList.add('component-row-hidden');
                        }}
                        visibleIndex++;
                    }}
                }});

                updateComponentCounters{tab_id}();
            }};

            window.prevPageInternal{tab_id} = function() {{
                if (currentPageInternal{tab_id} > 1) {{
                    currentPageInternal{tab_id}--;
                    applyPageInternal{tab_id}();
                }}
            }};

            window.nextPageInternal{tab_id} = function() {{
                const table = document.getElementById('componentTable-{tab_id}');
                const squadFilter = document.getElementById('squadFilter-{tab_id}');
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                const activeSquad = squadFilter ? squadFilter.value : '';
                const activeComponent = componentFilter ? componentFilter.value : '';

                const rows = Array.from(table.querySelectorAll('tbody tr'));
                const matchingRows = rows.filter(row => {{
                    let matches = true;
                    if (activeSquad && row.dataset.squad !== activeSquad) matches = false;
                    if (activeComponent && row.dataset.component !== activeComponent) matches = false;
                    return matches;
                }});

                const totalPages = Math.ceil(matchingRows.length / COMPONENT_PAGE_SIZE);

                if (currentPageInternal{tab_id} < totalPages) {{
                    currentPageInternal{tab_id}++;
                    applyPageInternal{tab_id}();
                }}
            }};

            window.applyPageExternal{tab_id} = function() {{
                const table = document.getElementById('externalTable-{tab_id}');
                if (!table) return;

                const squadFilter = document.getElementById('squadFilter-{tab_id}');
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                const activeSquad = squadFilter ? squadFilter.value : '';
                const activeComponent = componentFilter ? componentFilter.value : '';

                const rows = Array.from(table.querySelectorAll('tbody tr'));

                // Determine which rows match current filters
                const matchingRows = rows.filter(row => {{
                    let matches = true;
                    if (activeSquad && row.dataset.squad !== activeSquad) matches = false;
                    if (activeComponent && row.dataset.component !== activeComponent) matches = false;
                    return matches;
                }});

                // Paginate only matching rows
                const startIdx = (currentPageExternal{tab_id} - 1) * COMPONENT_PAGE_SIZE;
                const endIdx = startIdx + COMPONENT_PAGE_SIZE;
                let visibleIndex = 0;

                rows.forEach(row => {{
                    const isMatching = matchingRows.includes(row);

                    if (!isMatching) {{
                        row.style.display = 'none';
                        row.classList.add('component-row-hidden');
                    }} else {{
                        if (visibleIndex >= startIdx && visibleIndex < endIdx) {{
                            row.style.display = '';
                            row.classList.remove('component-row-hidden');
                        }} else {{
                            row.style.display = 'none';
                            row.classList.add('component-row-hidden');
                        }}
                        visibleIndex++;
                    }}
                }});

                updateComponentCounters{tab_id}();
            }};

            window.prevPageExternal{tab_id} = function() {{
                if (currentPageExternal{tab_id} > 1) {{
                    currentPageExternal{tab_id}--;
                    applyPageExternal{tab_id}();
                }}
            }};

            window.nextPageExternal{tab_id} = function() {{
                const table = document.getElementById('externalTable-{tab_id}');
                const squadFilter = document.getElementById('squadFilter-{tab_id}');
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                const activeSquad = squadFilter ? squadFilter.value : '';
                const activeComponent = componentFilter ? componentFilter.value : '';

                const rows = Array.from(table.querySelectorAll('tbody tr'));
                const matchingRows = rows.filter(row => {{
                    let matches = true;
                    if (activeSquad && row.dataset.squad !== activeSquad) matches = false;
                    if (activeComponent && row.dataset.component !== activeComponent) matches = false;
                    return matches;
                }});

                const totalPages = Math.ceil(matchingRows.length / COMPONENT_PAGE_SIZE);

                if (currentPageExternal{tab_id} < totalPages) {{
                    currentPageExternal{tab_id}++;
                    applyPageExternal{tab_id}();
                }}
            }};

            // Component search function
            window.searchComponents{tab_id} = function(query) {{
                const componentTable = document.getElementById('componentTable-{tab_id}');
                const externalTable = document.getElementById('externalTable-{tab_id}');
                const searchTerm = query.toLowerCase().trim();

                [componentTable, externalTable].forEach(table => {{
                    if (!table) return;
                    table.querySelectorAll('tbody tr').forEach(row => {{
                        if (!searchTerm) {{
                            // Show based on hidden class
                            if (row.classList.contains('component-row-hidden')) {{
                                row.style.display = 'none';
                            }} else {{
                                row.style.display = '';
                            }}
                        }} else {{
                            const componentName = row.dataset.component.toLowerCase();
                            row.style.display = componentName.includes(searchTerm) ? 'table-row' : 'none';
                        }}
                    }});
                }});

                updateComponentCounters{tab_id}();
            }};

            // Squad filter function
            window.filterBySquad{tab_id} = function(squad) {{
                // Repopulate component dropdown with only components from selected squad
                populateComponentDropdown{tab_id}(squad || null);

                // Reset component filter when squad changes
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                if (componentFilter) componentFilter.value = '';

                // Reset to page 1 and apply pagination with filter
                // applyPage functions will handle showing/hiding based on squad
                currentPageInternal{tab_id} = 1;
                currentPageExternal{tab_id} = 1;
                applyPageInternal{tab_id}();
                applyPageExternal{tab_id}();
            }};

            // Component filter function
            window.filterByComponent{tab_id} = function(component) {{
                const componentTable = document.getElementById('componentTable-{tab_id}');
                const externalTable = document.getElementById('externalTable-{tab_id}');

                [componentTable, externalTable].forEach(table => {{
                    if (!table) return;
                    table.querySelectorAll('tbody tr').forEach((row, index) => {{
                        if (!component) {{
                            // Reset to default: show top 15, hide rest
                            if (row.classList.contains('component-row-hidden')) {{
                                row.style.display = 'none';
                            }} else {{
                                row.style.display = '';
                            }}
                        }} else {{
                            const rowComponent = row.dataset.component;
                            // Show matching rows even if they're in hidden class
                            row.style.display = rowComponent === component ? 'table-row' : 'none';
                        }}
                    }});
                }});
            }};

            // Populate component dropdown (optionally filtered by squad)
            window.populateComponentDropdown{tab_id} = function(filterBySquad) {{
                const componentFilter = document.getElementById('componentFilter-{tab_id}');
                if (!componentFilter) return;

                // Clear existing options (except "All Components")
                componentFilter.innerHTML = '<option value="">All Components</option>';

                const components = new Set();
                const componentTable = document.getElementById('componentTable-{tab_id}');
                const externalTable = document.getElementById('externalTable-{tab_id}');

                [componentTable, externalTable].forEach(table => {{
                    if (!table) return;
                    table.querySelectorAll('tbody tr').forEach(row => {{
                        const comp = row.dataset.component;
                        const squad = row.dataset.squad;

                        // If filtering by squad, only include components from that squad
                        if (!filterBySquad || squad === filterBySquad) {{
                            if (comp) components.add(comp);
                        }}
                    }});
                }});

                Array.from(components).sort().forEach(comp => {{
                    const option = document.createElement('option');
                    option.value = comp;
                    option.textContent = comp;
                    componentFilter.appendChild(option);
                }});
            }};

            // Initial population
            populateComponentDropdown{tab_id}(null);
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

    # Generate comparison cards with health scores, sorted by score (worst first)
    card_data = [(rel, hist, *generate_comparison_card(rel, hist)) for rel, hist in releases.items()]
    card_data.sort(key=lambda x: -x[2])  # Sort by health_score descending
    comparison_cards = '\n'.join([card[3] for card in card_data])  # Extract HTML

    # Generate component CVE data for drill-down
    component_cve_data_js = generate_component_cve_data_js(releases, cve_descriptions)

    # Generate cross-release CVE table
    cross_release_table = generate_cross_release_cve_table(releases, cve_descriptions)

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
        cross_release_table=cross_release_table,
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
