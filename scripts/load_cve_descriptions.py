#!/usr/bin/env python3
"""Load CVE descriptions from Grype scan results"""

import json
from pathlib import Path


def load_cve_descriptions(json_dir='reports'):
    """Load CVE descriptions from Grype JSON files

    Returns:
        dict: {cve_id: {description, cvss_score}}
    """
    # Try to find most recent scan JSONs
    reports_path = Path(json_dir)

    # Look for version directories (e.g., 2.17.0)
    version_dirs = list(reports_path.glob('*/json'))
    if not version_dirs:
        return {}

    # Use most recent (assume highest version number or latest mtime)
    latest_dir = max(version_dirs, key=lambda p: p.stat().st_mtime)

    cve_desc_map = {}

    for json_file in latest_dir.glob('*_grype.json'):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            for match in data.get('matches', []):
                vuln = match.get('vulnerability', {})
                cve_id = vuln.get('id')
                description = vuln.get('description', '')

                # Extract CVSS score if available
                cvss_score = None
                cvss_list = vuln.get('cvss', [])
                if cvss_list and isinstance(cvss_list, list) and len(cvss_list) > 0:
                    # Get first CVSS entry
                    cvss_entry = cvss_list[0]
                    if isinstance(cvss_entry, dict):
                        metrics = cvss_entry.get('metrics', {})
                        cvss_score = metrics.get('baseScore')

                if cve_id and cve_id not in cve_desc_map:
                    cve_desc_map[cve_id] = {
                        'description': description,
                        'cvss_score': cvss_score
                    }
        except Exception:
            continue

    return cve_desc_map
