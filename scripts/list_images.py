#!/usr/bin/env python3
"""List all images from extras/*.json files"""

import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def main():
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')
    show_full_digest = os.getenv('SHOW_FULL_DIGEST', 'false').lower() == 'true'

    console.print(f"[blue]Listing all images from {extras_dir}...[/blue]\n")

    extras_path = Path(extras_dir)
    if not extras_path.exists():
        console.print(f"[red]Error: {extras_dir} directory not found[/red]")
        sys.exit(1)

    json_files = sorted(extras_path.glob('*.json'))
    if not json_files:
        console.print(f"[red]No JSON files found in {extras_dir}[/red]")
        sys.exit(1)

    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                images = json.load(f)

            # Create table for this file (optimized for 80-column terminals)
            table = Table(
                title=f"Images from {json_file.name}",
                show_header=True,
                header_style="bold cyan",
                show_lines=False,
                width=78  # Force narrower width to fit in 80 cols
            )
            table.add_column("", justify="center", width=1, no_wrap=True)  # Status icon
            table.add_column("Image Key", style="cyan", no_wrap=True, overflow="ellipsis")
            table.add_column("Digest", style="magenta", no_wrap=True, width=12)
            table.add_column("G", justify="center", width=1, no_wrap=True)  # Git status

            for image in images:
                image_key = image.get('image-key', 'unknown')
                image_remote = image.get('image-remote', '')
                image_name = image.get('image-name', '')
                image_digest = image.get('image-digest', '')
                git_url = image.get('git-url', '')
                git_rev = image.get('git-revision', '')

                # Format digest
                if show_full_digest:
                    digest_display = image_digest
                else:
                    # Show short hash (12 chars after sha256:)
                    if image_digest.startswith('sha256:'):
                        digest_display = image_digest[7:19]  # Skip sha256:, take 12 chars
                    else:
                        digest_display = image_digest[:12]

                # Format git info
                if git_url and git_rev:
                    git_info = "✓"
                else:
                    git_info = "-"

                # Color code based on digest type
                if image_digest.startswith('sha256:000000'):
                    digest_style = "red"
                    status_icon = "⚠️"
                else:
                    digest_style = "green"
                    status_icon = "✓"

                table.add_row(
                    status_icon,
                    image_key,
                    f"[{digest_style}]{digest_display}[/{digest_style}]",
                    git_info
                )

            console.print(table)
            console.print()

            # Print summary
            total_images = len(images)
            dummy_count = sum(1 for img in images if img.get('image-digest', '').startswith('sha256:000000'))
            real_count = total_images - dummy_count
            git_count = sum(1 for img in images if img.get('git-url'))

            summary = (
                f"Total: {total_images} images  |  "
                f"[green]Real SHAs: {real_count}[/green]  |  "
                f"[red]Placeholders: {dummy_count}[/red]  |  "
                f"[blue]With Git Info: {git_count}[/blue]"
            )
            console.print(Panel(summary, border_style="blue", padding=(0, 2)))
            console.print()

        except json.JSONDecodeError as e:
            console.print(f"[red]Error parsing {json_file}: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Error reading {json_file}: {e}[/red]")


if __name__ == '__main__':
    main()
