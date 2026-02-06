"""Watch command implementation."""

import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Sequence

from egresslens.docker_runner import run_docker_command
from egresslens.metadata import count_events_from_jsonl, generate_metadata, write_metadata
from egresslens.strace_parser import parse_to_jsonl


def watch_command(
    command: Sequence[str],
    output_dir: Path,
    image: str,
) -> int:
    """Execute watch command to monitor network egress.

    Args:
        command: Command to run as a sequence of strings
        output_dir: Directory to write output files
        mode: Execution mode ('docker' or 'host')
        image: Docker image to use (only for docker mode)
        no_enrich: Whether to disable DNS enrichment

    Returns:
        Exit code from the executed command
    """
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get current working directory
    cwd = Path.cwd()

    # Prepare paths
    strace_path = output_dir / "egress.strace"
    jsonl_path = output_dir / "egress.jsonl"
    metadata_path = output_dir / "run.json"

    # Record start time
    start_time = datetime.now()

    # Run command in Docker with strace (docker-only). Also capture container logs.
    logs_path = output_dir / "container.log"
    exit_code, error = run_docker_command(
        command=list(command),
        work_dir=cwd,
        image=image,
        strace_output_path=strace_path,
        logs_output_path=logs_path,
    )
    if error:
        print(f"Warning: {error}", file=__import__("sys").stderr)

    # Record end time
    end_time = datetime.now()

    # Parse strace output to JSONL
    if strace_path.exists():
        parse_to_jsonl(strace_path, jsonl_path)
    else:
        # Create empty JSONL file if strace output doesn't exist
        jsonl_path.touch()

    # Count events from JSONL
    total_events, unique_dst_ips, unique_dst_ip_ports = count_events_from_jsonl(jsonl_path)

    # Generate metadata
    run_id = str(uuid.uuid4())
    metadata = generate_metadata(
        run_id=run_id,
        start_time=start_time,
        end_time=end_time,
        exit_code=exit_code,
        mode="docker",
        image=image,
        command=list(command),
        cwd=cwd,
        total_events=total_events,
        unique_dst_ips=unique_dst_ips,
        unique_dst_ip_ports=unique_dst_ip_ports,
    )

    # Write metadata
    write_metadata(metadata, metadata_path)

    # Print summary to user
    output_dir_abs = output_dir.absolute()
    print(f"\n✓ Command completed with exit code {exit_code}", file=sys.stdout)
    print(f"  Output directory: {output_dir_abs}", file=sys.stdout)
    print(f"  Network events captured: {total_events}", file=sys.stdout)
    if total_events > 0:
        print(f"  Unique destination IPs: {unique_dst_ips}", file=sys.stdout)
        print(f"  Unique destination IP:port pairs: {unique_dst_ip_ports}", file=sys.stdout)
    print(f"  Files written:", file=sys.stdout)
    print(f"    - {jsonl_path.relative_to(output_dir)} ({total_events} events)", file=sys.stdout)
    print(f"    - {metadata_path.relative_to(output_dir)} (metadata)", file=sys.stdout)
    if strace_path.exists() and strace_path.stat().st_size > 0:
        print(f"    - {strace_path.relative_to(output_dir)} (raw strace output)", file=sys.stdout)
    if logs_path.exists() and logs_path.stat().st_size > 0:
        print(f"    - {logs_path.relative_to(output_dir)} (container logs)", file=sys.stdout)
    # Command stdout/stderr captured by strace wrapper
    cmd_stdout = output_dir / "cmd_stdout"
    cmd_stderr = output_dir / "cmd_stderr"
    if cmd_stdout.exists() and cmd_stdout.stat().st_size > 0:
        print(f"    - {cmd_stdout.relative_to(output_dir)} (command stdout)", file=sys.stdout)
    if cmd_stderr.exists() and cmd_stderr.stat().st_size > 0:
        print(f"    - {cmd_stderr.relative_to(output_dir)} (command stderr)", file=sys.stdout)

    return exit_code
