#!/usr/bin/env python3
"""Scan all images for CVEs using Trivy"""

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


def check_trivy_available():
    """Check if trivy is available"""
    try:
        subprocess.run(['trivy', '--version'], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def get_podman_socket():
    """Detect podman socket path for Trivy to use"""
    try:
        result = subprocess.run(
            ['podman', 'machine', 'inspect', 'podman-machine-default'],
            capture_output=True,
            timeout=10
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            # podman machine inspect returns an array
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            socket_path = data.get('ConnectionInfo', {}).get('PodmanSocket', {}).get('Path')
            if socket_path and os.path.exists(socket_path):
                return socket_path
    except:
        pass
    return None


def scan_image_trivy(image_ref, output_file, severity, timeout, format_type, podman_socket=None):
    """Scan image with Trivy (tries remote scan first, falls back to local download)"""

    # Set up environment with podman socket and auth if available
    env = os.environ.copy()
    if podman_socket:
        env['DOCKER_HOST'] = f'unix://{podman_socket}'

    # Use podman's auth file for registry authentication
    # Trivy uses Docker config format, so point DOCKER_CONFIG to containers dir
    containers_dir = os.path.expanduser('~/.config/containers')
    auth_file = os.path.join(containers_dir, 'auth.json')
    if os.path.exists(auth_file):
        # Copy auth.json to config.json if it doesn't exist
        config_file = os.path.join(containers_dir, 'config.json')
        if not os.path.exists(config_file):
            import shutil
            shutil.copy(auth_file, config_file)
        env['DOCKER_CONFIG'] = containers_dir

    # Try remote scanning first (faster, no download)
    try:
        cmd_remote = [
            'trivy', 'image',
            '--image-src', 'remote',
            '--severity', severity,
            '--timeout', timeout,
            '--format', format_type,
            image_ref
        ]

        # Suppress INFO/WARN logs when using JSON format for clean JSON output
        if format_type == 'json':
            cmd_remote.insert(2, '--quiet')

        with open(output_file, 'w') as f:
            result = subprocess.run(
                cmd_remote,
                stdout=f,
                stderr=subprocess.PIPE,
                timeout=600,  # 10 minute timeout
                env=env
            )

        if result.returncode == 0:
            return True

        # Remote scan failed, try local scan (download image)
        # console.print(f"[yellow]Remote scan failed, attempting local scan (downloading image)...[/yellow]")

    except subprocess.TimeoutExpired:
        pass  # Fall through to local scan
    except Exception:
        pass  # Fall through to local scan

    # Fall back to local scanning (downloads image)
    try:
        cmd_local = [
            'trivy', 'image',
            '--severity', severity,
            '--timeout', timeout,
            '--format', format_type,
            image_ref
        ]

        # Suppress INFO/WARN logs when using JSON format for clean JSON output
        if format_type == 'json':
            cmd_local.insert(2, '--quiet')

        with open(output_file, 'w') as f:
            result = subprocess.run(
                cmd_local,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=600,  # 10 minute timeout
                env=env
            )

        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        with open(output_file, 'a') as f:
            f.write(f"\nError during scan: {e}\n")
        return False


def parse_trivy_json_for_counts(scan_file):
    """Parse Trivy JSON to get vulnerability counts by severity"""
    try:
        with open(scan_file, 'r') as f:
            data = json.load(f)

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}

        if 'Results' in data:
            for result in data.get('Results', []):
                for vuln in result.get('Vulnerabilities', []):
                    severity = vuln.get('Severity', '').upper()
                    if severity == 'CRITICAL':
                        counts['critical'] += 1
                    elif severity == 'HIGH':
                        counts['high'] += 1
                    elif severity == 'MEDIUM':
                        counts['medium'] += 1
                    elif severity == 'LOW':
                        counts['low'] += 1
                    counts['total'] += 1

        return counts
    except:
        return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}


def count_vulnerabilities(scan_file, format_type):
    """Try to count vulnerabilities from scan file"""
    try:
        if format_type == 'json':
            with open(scan_file, 'r') as f:
                data = json.load(f)
                count = 0
                if 'Results' in data:
                    for result in data.get('Results', []):
                        count += len(result.get('Vulnerabilities', []))
                return count
        else:
            # For table format, count CVE lines
            with open(scan_file, 'r') as f:
                return sum(1 for line in f if 'CVE-' in line)
    except:
        return 0


def main():
    extras_dir = os.getenv('EXTRAS_DIR', 'extras')
    reports_dir = os.getenv('REPORTS_DIR', 'reports')
    severity = os.getenv('TRIVY_SEVERITY', 'HIGH,CRITICAL')
    timeout = os.getenv('TRIVY_TIMEOUT', '10m')
    output_json = os.getenv('OUTPUT_JSON', 'false').lower() == 'true'
    format_type = 'json' if output_json else 'table'
    icsp_config_path = os.getenv('ICSP_CONFIG', 'icsp-config.json')
    acm_version = os.getenv('ACM_VERSION', '')

    if not check_trivy_available():
        console.print("[red]Error: trivy is not installed[/red]")
        console.print("Install from: https://github.com/aquasecurity/trivy")
        sys.exit(1)

    # Detect podman socket for Trivy to use
    podman_socket = get_podman_socket()
    auth_file = os.path.expanduser('~/.config/containers/auth.json')
    has_auth = os.path.exists(auth_file)

    runtime_info = []
    if podman_socket:
        runtime_info.append(f"[green]Podman socket:[/green] {podman_socket}")
    if has_auth:
        runtime_info.append(f"[green]Registry auth:[/green] {auth_file}")

    if runtime_info:
        console.print(Panel(
            "\n".join(runtime_info),
            title="Container Runtime",
            border_style="green"
        ))
    else:
        console.print("[yellow]No podman socket or auth detected (will try direct registry access)[/yellow]\n")

    # Determine version from extras files if not provided
    if not acm_version:
        extras_path = Path(extras_dir)
        json_files = sorted(extras_path.glob('*.json'))
        if json_files:
            acm_version = json_files[0].stem  # e.g., "2.17.0"

    # Create organized reports directory structure
    # reports/2.17.0/json/ or reports/2.17.0/text/
    if acm_version:
        version_dir = Path(reports_dir) / acm_version
        subdir = 'json' if format_type == 'json' else 'text'
        output_dir = version_dir / subdir

        output_dir.mkdir(parents=True, exist_ok=True)

        # Set reports_dir to version directory
        reports_dir = str(version_dir)

        console.print(f"[blue]Reports will be saved to: {output_dir}[/blue]\n")
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

    format_label = "JSON" if format_type == 'json' else "text"
    console.print(f"[blue]Scanning images for vulnerabilities ({format_label} output)...[/blue]")
    console.print(f"Severity filter: [yellow]{severity}[/yellow]\n")

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

        # Summary file goes in version directory root
        summary_file = Path(reports_dir) / f"{base_name}_cve_summary.txt"

        try:
            with open(json_file, 'r') as f:
                images = json.load(f)
        except Exception as e:
            console.print(f"[red]Error reading {json_file}: {e}[/red]")
            continue

        total_images = 0
        scanned = 0
        failed = 0
        total_scan_time = 0.0
        results = []  # Store results for table display

        with open(summary_file, 'w') as summary:
            summary.write(f"CVE Scan Summary - {datetime.now()}\n")
            summary.write(f"Severity Filter: {severity}\n")
            if icsp_mirrors:
                summary.write(f"ICSP Mirrors: {len(icsp_mirrors)} configured\n")
            summary.write("=" * 60 + "\n\n")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Scanning images...", total=len(images))

                for image in images:
                    image_key = image.get('image-key', 'unknown')
                    image_remote = image.get('image-remote', '')
                    image_name = image.get('image-name', '')
                    image_digest = image.get('image-digest', '')
                    full_image = f"{image_remote}/{image_name}@{image_digest}"

                    # Apply ICSP redirect if configured
                    scan_image, redirect_source = apply_icsp_redirect(full_image, icsp_mirrors)

                    progress.update(task, description=f"[cyan]Scanning {image_key}...")

                    # Determine output file extension and path
                    ext = 'json' if format_type == 'json' else 'txt'
                    if acm_version:
                        subdir = 'json' if format_type == 'json' else 'text'
                        scan_file = Path(reports_dir) / subdir / f"{base_name}_{image_key}_trivy.{ext}"
                    else:
                        scan_file = Path(reports_dir) / f"{base_name}_{image_key}_trivy.{ext}"

                    # Time the scan
                    start_time = time.time()
                    result = scan_image_trivy(scan_image, scan_file, severity, timeout, format_type, podman_socket)
                    elapsed = time.time() - start_time
                    total_scan_time += elapsed

                    # Try to get vulnerability details
                    if result and format_type == 'json':
                        vuln_data = parse_trivy_json_for_counts(scan_file)
                    else:
                        vuln_data = count_vulnerabilities(scan_file, format_type) if result else 0

                    if result:
                        results.append((image_key, "✓ OK", f"{elapsed:.1f}s", vuln_data, "green"))
                        if redirect_source:
                            summary.write(f"✓ {image_key}: {full_image} ({elapsed:.1f}s)\n")
                            summary.write(f"  → Scanned via ICSP mirror: {scan_image}\n")
                        else:
                            summary.write(f"✓ {image_key}: {full_image} ({elapsed:.1f}s)\n")

                        if isinstance(vuln_data, dict):
                            total_vulns = vuln_data.get('total', 0)
                            if total_vulns > 0:
                                summary.write(f"  Found {total_vulns} vulnerabilities: ")
                                summary.write(f"{vuln_data.get('critical', 0)} CRIT, ")
                                summary.write(f"{vuln_data.get('high', 0)} HIGH, ")
                                summary.write(f"{vuln_data.get('medium', 0)} MED, ")
                                summary.write(f"{vuln_data.get('low', 0)} LOW\n")
                        elif vuln_data > 0:
                            summary.write(f"  Found {vuln_data} vulnerabilities\n")

                        scanned += 1
                    else:
                        results.append((image_key, "✗ FAILED", f"{elapsed:.1f}s", 0, "red"))
                        if redirect_source:
                            summary.write(f"✗ {image_key}: {full_image} ({elapsed:.1f}s)\n")
                            summary.write(f"  → Failed even with ICSP mirror: {scan_image}\n")
                        else:
                            summary.write(f"✗ {image_key}: {full_image} - Scan failed ({elapsed:.1f}s)\n")
                        failed += 1

                    total_images += 1
                    progress.advance(task)

            summary.write(f"\n{'=' * 60}\n")
            summary.write(f"Summary: {scanned} scanned, {failed} failed out of {total_images} total\n")
            summary.write(f"Total scan time: {total_scan_time:.1f}s (avg: {total_scan_time/total_images:.1f}s per image)\n")

        file_elapsed = time.time() - file_start_time

        # Display results table
        console.print()
        table = Table(title="CVE Scan Results", show_header=True, header_style="bold cyan")
        table.add_column("Image", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Time", justify="right", style="magenta")
        table.add_column("CRIT", justify="right", style="red")
        table.add_column("HIGH", justify="right", style="yellow")
        table.add_column("MED", justify="right", style="blue")
        table.add_column("LOW", justify="right", style="green")
        table.add_column("Total", justify="right", style="bold")

        for img_key, status, time_val, vulns, color in results:
            if isinstance(vulns, dict):
                # Show breakdown by severity
                crit = str(vulns.get('critical', 0)) if vulns.get('critical', 0) > 0 else "-"
                high = str(vulns.get('high', 0)) if vulns.get('high', 0) > 0 else "-"
                med = str(vulns.get('medium', 0)) if vulns.get('medium', 0) > 0 else "-"
                low = str(vulns.get('low', 0)) if vulns.get('low', 0) > 0 else "-"
                total = str(vulns.get('total', 0)) if vulns.get('total', 0) > 0 else "-"
                table.add_row(img_key, f"[{color}]{status}[/{color}]", time_val, crit, high, med, low, total)
            else:
                # Old format or failed scan
                vuln_str = str(vulns) if vulns > 0 else "-"
                table.add_row(img_key, f"[{color}]{status}[/{color}]", time_val, "-", "-", "-", "-", vuln_str)
        console.print(table)

        # Display summary panel
        console.print()
        summary_text = (
            f"[green]✓ {scanned} scanned[/green]  [red]✗ {failed} failed[/red]  Total: {total_images}\n"
            f"Scan time: {total_scan_time:.1f}s (avg: {total_scan_time/total_images:.1f}s per image)\n"
            f"Total elapsed: {file_elapsed:.1f}s\n"
            f"Summary saved to: [cyan]{summary_file}[/cyan]"
        )
        console.print(Panel(summary_text, title="Summary", border_style="blue"))

    console.print(f"\n[bold green]✓ CVE scanning complete. Reports in {reports_dir}[/bold green]")


if __name__ == '__main__':
    main()
