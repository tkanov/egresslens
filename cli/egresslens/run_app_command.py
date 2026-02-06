"""Run-app command implementation for Python applications."""

import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Sequence, Optional

from egresslens.docker_runner import run_python_app
from egresslens.metadata import count_events_from_jsonl, generate_metadata, write_metadata
from egresslens.run_app import validate_app_directory, AppValidationError
from egresslens.strace_parser import parse_to_jsonl


def run_app_command(
    app_path: str,
    app_args: Sequence[str],
    output_dir: Path,
    image: str,
) -> int:
    """Execute run-app command to monitor network egress from Python applications.

    Args:
        app_path: Path to the Python app directory
        app_args: Arguments to pass to the app
        output_dir: Directory to write output files
        image: Docker image to use

    Returns:
        Exit code from the executed app
    """
    # Validate app directory and get metadata
    try:
        app_meta = validate_app_directory(app_path)
    except AppValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare paths
    app_path_obj = Path(app_meta["app_path"])
    strace_path = output_dir / "egress.strace"
    jsonl_path = output_dir / "egress.jsonl"
    metadata_path = output_dir / "run.json"

    # Record start time
    start_time = datetime.now()

    # Run Python app in Docker with strace
    exit_code, error = run_python_app(
        app_path=app_path_obj,
        entry_point=app_meta["entry_point"],
        app_args=list(app_args),
        has_requirements=app_meta["has_requirements"],
        image=image,
        strace_output_path=strace_path,
    )
    if error:
        print(f"Warning: {error}", file=sys.stderr)

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

    # Build command representation for metadata
    if app_meta["entry_point"] == "__main__.py":
        command_repr = ["python", "-m", app_path_obj.name] + list(app_args)
    else:
        command_repr = ["python", app_meta["entry_point"]] + list(app_args)

    # Generate metadata
    run_id = str(uuid.uuid4())
    metadata = generate_metadata(
        run_id=run_id,
        start_time=start_time,
        end_time=end_time,
        exit_code=exit_code,
        mode="docker",
        image=image,
        command=command_repr,
        cwd=app_path_obj,
        total_events=total_events,
        unique_dst_ips=unique_dst_ips,
        unique_dst_ip_ports=unique_dst_ip_ports,
    )

    # Write metadata
    write_metadata(metadata, metadata_path)

    # Print summary
    print(f"\n✓ Run complete (exit code: {exit_code})")
    print(f"  Run ID: {run_id}")
    print(f"  Output: {output_dir.absolute()}")
    print(f"  Events: {total_events} network events captured")
    print(f"  Unique destinations: {unique_dst_ips} IPs, {unique_dst_ip_ports} IP:port pairs")
    if app_meta["has_requirements"]:
        print(f"  Dependencies: Installed from requirements.txt")

    return exit_code
