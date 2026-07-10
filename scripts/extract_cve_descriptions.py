#!/usr/bin/env python3
"""Extract CVE descriptions from grype JSONs to cached file"""

import json
import sys
from pathlib import Path

# Add scripts dir to path
sys.path.insert(0, str(Path(__file__).parent))

from load_cve_descriptions import load_cve_descriptions


def extract_cve_descriptions(reports_dir='reports', output_file=None):
    """Extract CVE descriptions from grype JSONs and save to cache file

    Args:
        reports_dir: Directory containing grype scan results
        output_file: Output path for descriptions JSON (default: reports/cve-descriptions.json)

    Returns:
        dict: Extracted descriptions
    """
    if output_file is None:
        output_file = Path(reports_dir) / 'cve-descriptions.json'
    else:
        output_file = Path(output_file)

    print(f"Extracting CVE descriptions from {reports_dir}...")
    descriptions = load_cve_descriptions(reports_dir)

    if not descriptions:
        print("⚠ No CVE descriptions found")
        return {}

    print(f"✓ Extracted {len(descriptions)} CVE descriptions")

    # Save to file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(descriptions, f, indent=2)

    print(f"✓ Saved to {output_file}")

    # Show stats
    with_cvss = sum(1 for v in descriptions.values() if v.get('cvss_score'))
    with_desc = sum(1 for v in descriptions.values() if v.get('description') and v['description'] != 'No description available')

    print(f"  - {with_cvss} with CVSS scores")
    print(f"  - {with_desc} with descriptions")

    return descriptions


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Extract CVE descriptions from grype scan results')
    parser.add_argument('--reports-dir', default='reports',
                       help='Reports directory containing grype JSONs (default: reports)')
    parser.add_argument('--output',
                       help='Output file path (default: reports/cve-descriptions.json)')

    args = parser.parse_args()

    descriptions = extract_cve_descriptions(args.reports_dir, args.output)

    if not descriptions:
        sys.exit(1)
