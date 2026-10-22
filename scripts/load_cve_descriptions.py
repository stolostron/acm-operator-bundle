#!/usr/bin/env python3
"""Load CVE descriptions from Grype scan results"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_cve_descriptions(json_dir='reports', skip_cache=False):
    """Load CVE descriptions from cached file or Grype JSON files

    Args:
        json_dir: Directory containing reports
        skip_cache: If True, ignore cached file and parse Grype JSONs directly

    Returns:
        dict: {cve_id: {description, cvss_score}}
    """
    reports_path = Path(json_dir)

    if not skip_cache:
        cache_file = reports_path / 'cve-descriptions.json'
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                for entry in cached.values():
                    desc = entry.get('description', '')
                    if not desc or desc.startswith('Placeholder:'):
                        entry['description'] = 'No description available'
                return cached
            except Exception as e:
                logger.warning("Failed to load CVE description cache %s: %s", cache_file, e)

    # Find all Grype JSON files recursively
    json_files = list(reports_path.rglob('*_grype.json'))
    if not json_files:
        return {}

    cve_desc_map = {}

    for json_file in json_files:
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
                    if not description or description.startswith('Placeholder:'):
                        description = 'No description available'
                    cve_desc_map[cve_id] = {
                        'description': description,
                        'cvss_score': cvss_score
                    }
        except Exception:
            continue

    return cve_desc_map
