#!/usr/bin/env python3
"""Verify all images are pullable/accessible"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()


def load_icsp_config(config_path):
    """Load ICSP (ImageContentSourcePolicy) configuration from JSON file"""
    if not config_path or not os.path.exists(config_path):
        return None

    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config.get('mirrors', [])
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load ICSP config from {config_path}: {e}[/yellow]")
        return None


def apply_icsp_redirect(image_ref, icsp_mirrors):
    """Apply ICSP registry redirects to an image reference"""
    if not icsp_mirrors:
        return image_ref, None

    # Parse image reference: registry/repo/image@sha256:digest
    for mirror in icsp_mirrors:
        source = mirror.get('source', '')
        mirror_registry = mirror.get('mirror', '')

        if source and mirror_registry and image_ref.startswith(source):
            redirected = image_ref.replace(source, mirror_registry, 1)
            return redirected, source

    return image_ref, None


def check_tool_available(tool):
    """Check if a tool is available in PATH"""
    try:
        subprocess.run([tool, '--version'], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


def verify_with_skopeo(image_ref, override_arch=None, override_os=None):
    """Verify image using skopeo inspect"""
    try:
        cmd = ['skopeo', 'inspect', '--raw']

        if override_arch:
            cmd.extend(['--override-arch', override_arch])

        if override_os:
            cmd.extend(['--override-os', override_os])

        cmd.append(f'docker://{image_ref}')

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def verify_with_podman(image_ref):
    """Verify image using podman"""
    try:
        # Try to inspect first
        result = subprocess.run(
            ['podman', 'image', 'inspect', image_ref],
            capture_output=True,
            timeout=30
        )
        if result.returncode == 0:
            return True

        # If not found locally, try to pull
        result = subprocess.run(
            ['podman', 'pull', '-q', image_ref],
            capture_output=True,
            timeout=120
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def main():
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')
    reports_dir = os.getenv('REPORTS_DIR', 'reports')
    use_podman = os.getenv('USE_PODMAN', 'false').lower() == 'true'
    override_arch = os.getenv('OVERRIDE_ARCH')
    override_os = os.getenv('OVERRIDE_OS')
    icsp_config_path = os.getenv('ICSP_CONFIG', 'icsp-config.json')
    acm_version = os.getenv('ACM_VERSION', '')

    # Determine version from extras files if not provided
    if not acm_version:
        extras_path = Path(extras_dir)
        if extras_path.exists():
            json_files = sorted(extras_path.glob('*.json'))
            if json_files:
                acm_version = json_files[0].stem  # e.g., "2.17.0"

    # Create organized reports directory structure
    if acm_version:
        version_dir = Path(reports_dir) / acm_version
        version_dir.mkdir(parents=True, exist_ok=True)
        reports_dir = str(version_dir)
        console.print(f"[blue]Verification reports will be saved to: {version_dir}[/blue]\n")
    else:
        Path(reports_dir).mkdir(exist_ok=True)

    # Load ICSP configuration
    icsp_mirrors = load_icsp_config(icsp_config_path)
    if icsp_mirrors:
        mirror_lines = "\n".join([f"  {m['source']} → {m['mirror']}" for m in icsp_mirrors])
        console.print(Panel(
            f"[green]Loaded {len(icsp_mirrors)} ICSP mirror(s):[/green]\n{mirror_lines}",
            title="ICSP Configuration",
            border_style="green"
        ))
    else:
        console.print("[yellow]No ICSP config loaded (set ICSP_CONFIG env var to use)[/yellow]\n")

    # Determine which tool to use
    if use_podman:
        if not check_tool_available('podman'):
            console.print("[red]Error: podman is not installed[/red]")
            sys.exit(1)
        tool_name = "podman"
        verify_func = verify_with_podman
        if override_arch or override_os:
            console.print("[yellow]Warning: OVERRIDE_ARCH and OVERRIDE_OS are only supported with skopeo[/yellow]")
        console.print("[blue]Verifying image accessibility with podman...[/blue]")
    else:
        if not check_tool_available('skopeo'):
            console.print("[red]Error: skopeo is not installed. Install it or use USE_PODMAN=true[/red]")
            sys.exit(1)
        tool_name = "skopeo"
        verify_func = lambda img: verify_with_skopeo(img, override_arch, override_os)
        arch_info = f" (arch: {override_arch})" if override_arch else ""
        os_info = f" (os: {override_os})" if override_os else ""
        console.print(f"[blue]Verifying image accessibility with skopeo{arch_info}{os_info}...[/blue]")

    extras_path = Path(extras_dir)
    if not extras_path.exists():
        console.print(f"[red]Error: {extras_dir} directory not found[/red]")
        sys.exit(1)

    json_files = sorted(extras_path.glob('*.json'))
    if not json_files:
        console.print(f"[red]No JSON files found in {extras_dir}[/red]")
        sys.exit(1)

    for json_file in json_files:
        console.print(f"\n[bold yellow]Processing: {json_file}[/bold yellow]")
        file_start_time = time.time()

        base_name = json_file.stem
        report_file = Path(reports_dir) / f"{base_name}_verify_report.txt"

        try:
            with open(json_file, 'r') as f:
                images = json.load(f)
        except Exception as e:
            console.print(f"[red]Error reading {json_file}: {e}[/red]")
            continue

        total = 0
        passed = 0
        failed = 0
        total_verify_time = 0.0
        results = []  # Store results for table display

        with open(report_file, 'w') as report:
            report.write(f"Image Verification Report - {datetime.now()}\n")
            report.write(f"Tool: {tool_name}\n")
            if override_arch:
                report.write(f"Architecture: {override_arch}\n")
            if override_os:
                report.write(f"OS: {override_os}\n")
            if icsp_mirrors:
                report.write(f"ICSP Mirrors: {len(icsp_mirrors)} configured\n")
            report.write("=" * 60 + "\n\n")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Verifying images...", total=len(images))

                for image in images:
                    image_key = image.get('image-key', 'unknown')
                    image_remote = image.get('image-remote', '')
                    image_name = image.get('image-name', '')
                    image_digest = image.get('image-digest', '')
                    full_image = f"{image_remote}/{image_name}@{image_digest}"

                    # Apply ICSP redirect if configured
                    verify_image, redirect_source = apply_icsp_redirect(full_image, icsp_mirrors)

                    progress.update(task, description=f"[cyan]Checking {image_key}...")

                    # Time the verification
                    start_time = time.time()
                    result = verify_func(verify_image)
                    elapsed = time.time() - start_time
                    total_verify_time += elapsed

                    if result:
                        results.append((image_key, "✓ OK", f"{elapsed:.1f}s", "green"))
                        if redirect_source:
                            report.write(f"✓ {image_key}: {full_image} ({elapsed:.1f}s)\n")
                            report.write(f"  → Verified via ICSP mirror: {verify_image}\n")
                        else:
                            report.write(f"✓ {image_key}: {full_image} ({elapsed:.1f}s)\n")
                        passed += 1
                    else:
                        results.append((image_key, "✗ FAILED", f"{elapsed:.1f}s", "red"))
                        if redirect_source:
                            report.write(f"✗ {image_key}: {full_image} ({elapsed:.1f}s)\n")
                            report.write(f"  → Failed even with ICSP mirror: {verify_image}\n")
                        else:
                            report.write(f"✗ {image_key}: {full_image} - NOT ACCESSIBLE ({elapsed:.1f}s)\n")
                        failed += 1

                    total += 1
                    progress.advance(task)

            report.write(f"\n{'=' * 60}\n")
            report.write(f"Summary: {passed} passed, {failed} failed out of {total} total\n")
            report.write(f"Total verification time: {total_verify_time:.1f}s (avg: {total_verify_time/total:.1f}s per image)\n")

        file_elapsed = time.time() - file_start_time

        # Display results table
        console.print()
        table = Table(title="Verification Results", show_header=True, header_style="bold cyan")
        table.add_column("Image", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Time", justify="right", style="magenta")

        for img_key, status, time_val, color in results:
            table.add_row(img_key, f"[{color}]{status}[/{color}]", time_val)
        console.print(table)

        # Display summary panel
        console.print()
        summary_text = (
            f"[green]✓ {passed} passed[/green]  [red]✗ {failed} failed[/red]  Total: {total}\n"
            f"Verification time: {total_verify_time:.1f}s (avg: {total_verify_time/total:.1f}s per image)\n"
            f"Total elapsed: {file_elapsed:.1f}s\n"
            f"Report saved to: [cyan]{report_file}[/cyan]"
        )
        console.print(Panel(summary_text, title="Summary", border_style="blue"))

    console.print(f"\n[bold green]✓ Verification complete. Reports in {reports_dir}[/bold green]")


if __name__ == '__main__':
    main()
