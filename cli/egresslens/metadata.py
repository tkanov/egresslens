"""Metadata generator for run information."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


def generate_metadata(
    run_id: str,
    start_time: datetime,
    end_time: datetime,
    exit_code: int,
    mode: str,
    image: Optional[str],
    command: list[str],
    cwd: Path,
    total_events: int,
    unique_dst_ips: int,
    unique_dst_ip_ports: int,
) -> dict:
    """Generate run metadata dictionary.

    Args:
        run_id: Unique run identifier
        start_time: Run start time
        end_time: Run end time
        exit_code: Exit code from command
        mode: Execution mode (docker/host)
        image: Docker image used (if docker mode)
        command: Command that was executed
        cwd: Current working directory
        total_events: Total number of events captured
        unique_dst_ips: Number of unique destination IPs
        unique_dst_ip_ports: Number of unique destination IP:port pairs

    Returns:
        Metadata dictionary
    """
    return {
        "run_id": run_id,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "exit_code": exit_code,
        "mode": mode,
        "image": image,
        "command": command,
        "cwd": str(cwd.absolute()),
        "counts": {
            "total_events": total_events,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ip_ports": unique_dst_ip_ports,
        },
    }


def write_metadata(metadata: dict, output_path: Path) -> None:
    """Write metadata to JSON file.

    Args:
        metadata: Metadata dictionary
        output_path: Path to write run.json
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def count_events_from_jsonl(jsonl_path: Path) -> tuple[int, int, int]:
    """Count events from JSONL file to compute statistics.

    Args:
        jsonl_path: Path to JSONL file

    Returns:
        Tuple of (total_events, unique_dst_ips, unique_dst_ip_ports)
    """
    if not jsonl_path.exists():
        return 0, 0, 0

    unique_ips = set()
    unique_ip_ports = set()
    total = 0

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                total += 1
                dst_ip = event.get("dst_ip")
                dst_port = event.get("dst_port")
                if dst_ip:
                    unique_ips.add(dst_ip)
                if dst_ip and dst_port:
                    unique_ip_ports.add(f"{dst_ip}:{dst_port}")
            except json.JSONDecodeError:
                continue

    return total, len(unique_ips), len(unique_ip_ports)
