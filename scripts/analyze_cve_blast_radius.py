#!/usr/bin/env python3
"""Analyze CVE blast radius - which CVEs affect most components"""

def analyze_blast_radius(scan, top_n=10):
    """Analyze which CVEs affect the most components

    Args:
        scan: Scan record with summary.cve_details
        top_n: Number of top CVEs to return

    Returns:
        List of dicts with CVE analysis
    """
    cve_details = scan.get('summary', {}).get('cve_details', [])

    if not cve_details:
        return []

    # Group by CVE ID
    cve_map = {}
    for detail in cve_details:
        cve_id = detail.get('cve_id')
        severity = detail.get('severity')
        component = detail.get('component')
        fixable = detail.get('fixable', False)
        fixed_versions = detail.get('fixed_versions', [])

        if cve_id not in cve_map:
            cve_map[cve_id] = {
                'cve_id': cve_id,
                'severity': severity,
                'components': set(),
                'fixable': fixable,
                'fixed_versions': set(),
                'sample_detail': detail  # Keep one detail for description extraction
            }

        cve_map[cve_id]['components'].add(component)
        # If ANY instance is fixable, mark as fixable
        if fixable:
            cve_map[cve_id]['fixable'] = True
        # Collect all fixed versions
        if fixed_versions:
            for ver in fixed_versions:
                cve_map[cve_id]['fixed_versions'].add(ver)

    # Convert to list and count components
    cve_list = []
    for cve_id, data in cve_map.items():
        # Format fixed versions
        fixed_vers = sorted(data['fixed_versions'])
        if len(fixed_vers) == 0:
            fix_display = 'None'
        elif len(fixed_vers) == 1:
            fix_display = fixed_vers[0]
        elif len(fixed_vers) <= 3:
            fix_display = ', '.join(fixed_vers)
        else:
            fix_display = f"{fixed_vers[0]} (+{len(fixed_vers)-1} more)"

        cve_list.append({
            'cve_id': cve_id,
            'severity': data['severity'],
            'component_count': len(data['components']),
            'components': list(data['components']),
            'fixable': data['fixable'],
            'fix_display': fix_display,
            'sample_detail': data['sample_detail']  # For description/CVSS extraction
        })

    # Sort by component count (blast radius)
    cve_list.sort(key=lambda x: x['component_count'], reverse=True)

    return cve_list[:top_n]
