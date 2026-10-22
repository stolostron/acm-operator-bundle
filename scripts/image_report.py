#!/usr/bin/env python3
"""Generate comprehensive image report"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class Colors:
    BLUE = '\033[0;34m'
    YELLOW = '\033[1;33m'
    GREEN = '\033[0;32m'
    NC = '\033[0m'


def main():
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')
    reports_dir = os.getenv('REPORTS_DIR', 'reports')

    # Create reports directory
    Path(reports_dir).mkdir(exist_ok=True)

    print(f"{Colors.BLUE}Generating comprehensive image report...{Colors.NC}")

    extras_path = Path(extras_dir)
    if not extras_path.exists():
        print(f"Error: {extras_dir} directory not found")
        sys.exit(1)

    json_files = sorted(extras_path.glob('*.json'))
    if not json_files:
        print(f"No JSON files found in {extras_dir}")
        sys.exit(1)

    for json_file in json_files:
        print(f"\n{Colors.YELLOW}Processing: {json_file}{Colors.NC}")

        base_name = json_file.stem
        report_file = Path(reports_dir) / f"{base_name}_comprehensive_report.txt"

        try:
            with open(json_file, 'r') as f:
                images = json.load(f)
        except Exception as e:
            print(f"{Colors.RED}Error reading {json_file}: {e}{Colors.NC}")
            continue

        # Group by registry
        registry_counts = defaultdict(int)
        for image in images:
            registry = image.get('image-remote', 'unknown')
            registry_counts[registry] += 1

        with open(report_file, 'w') as report:
            report.write(f"Comprehensive Image Report - {datetime.now()}\n")
            report.write("=" * 60 + "\n\n")

            report.write(f"Total Images: {len(images)}\n\n")

            report.write("Images by Registry:\n")
            report.write("-" * 60 + "\n")
            for registry in sorted(registry_counts.keys()):
                report.write(f"{registry}: {registry_counts[registry]} images\n")
            report.write("\n")

            report.write("Image Details:\n")
            report.write("-" * 60 + "\n")

            for image in images:
                image_key = image.get('image-key', 'unknown')
                image_remote = image.get('image-remote', '')
                image_name = image.get('image-name', '')
                image_digest = image.get('image-digest', '')
                git_url = image.get('git-url', 'N/A')
                git_revision = image.get('git-revision', 'N/A')
                full_image = f"{image_remote}/{image_name}@{image_digest}"

                report.write(f"\nImage Key: {image_key}\n")
                report.write(f"  Full Reference: {full_image}\n")
                report.write(f"  Registry: {image_remote}\n")
                report.write(f"  Name: {image_name}\n")
                report.write(f"  Digest: {image_digest}\n")
                report.write(f"  Git URL: {git_url}\n")
                report.write(f"  Git Revision: {git_revision}\n")

        print(f"Report saved to: {report_file}")

    print(f"\n{Colors.GREEN}Report generation complete. Reports in {reports_dir}{Colors.NC}")


if __name__ == '__main__':
    main()
