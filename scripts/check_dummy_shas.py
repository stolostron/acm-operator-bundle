#!/usr/bin/env python3
"""Check for dummy or flagged SHA digests"""

import json
import os
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def is_dummy_sha(digest):
    """Check if SHA looks like a dummy/test value"""
    if not digest:
        return True

    # Check for all zeros
    if re.match(r'^sha256:0+$', digest):
        return True

    # Check for test patterns
    if re.search(r'1234|test|dummy|fake|placeholder', digest.lower()):
        return True

    # Check for repetitive patterns (same char repeated)
    if re.match(r'^sha256:(.)\1+$', digest):
        return True

    return False


def is_valid_sha_format(digest):
    """Check if SHA has valid format (sha256: followed by 64 hex chars)"""
    if not digest:
        return False

    pattern = r'^sha256:[a-f0-9]{64}$'
    return bool(re.match(pattern, digest))


def main():
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')

    console.print("[blue]Checking for dummy/invalid SHA digests...[/blue]\n")

    extras_path = Path(extras_dir)
    if not extras_path.exists():
        console.print(f"[red]Error: {extras_dir} directory not found[/red]")
        sys.exit(1)

    json_files = sorted(extras_path.glob('*.json'))
    if not json_files:
        console.print(f"[red]No JSON files found in {extras_dir}[/red]")
        sys.exit(1)

    found_issues = 0
    issues = []

    for json_file in json_files:
        console.print(f"[yellow]Checking: {json_file}[/yellow]")

        try:
            with open(json_file, 'r') as f:
                images = json.load(f)

            for image in images:
                image_key = image.get('image-key', 'unknown')
                digest = image.get('image-digest', '')

                if is_dummy_sha(digest):
                    issues.append((image_key, digest, "DUMMY/PLACEHOLDER"))
                    found_issues += 1
                elif not is_valid_sha_format(digest):
                    issues.append((image_key, digest, "INVALID FORMAT"))
                    found_issues += 1

        except json.JSONDecodeError as e:
            console.print(f"[red]Error parsing {json_file}: {e}[/red]")
            found_issues += 1
        except Exception as e:
            console.print(f"[red]Error reading {json_file}: {e}[/red]")
            found_issues += 1

    console.print()
    if found_issues == 0:
        console.print(Panel("[bold green]✓ No dummy or invalid SHA digests found[/bold green]", border_style="green"))
    else:
        # Display issues in a table
        if issues:
            table = Table(title=f"Found {found_issues} Dummy/Invalid SHAs", show_header=True, header_style="bold yellow")
            table.add_column("Image", style="cyan")
            table.add_column("Digest", style="yellow")
            table.add_column("Issue Type", style="red")

            for img_key, digest, issue_type in issues:
                table.add_row(img_key, digest[:50] + "..." if len(digest) > 50 else digest, issue_type)

            console.print(table)

        console.print(Panel(
            f"[bold yellow]Found {found_issues} dummy/invalid SHAs[/bold yellow]",
            border_style="yellow"
        ))

    # Always exit successfully - this is a reporting command, not a validation
    sys.exit(0)


if __name__ == '__main__':
    main()
