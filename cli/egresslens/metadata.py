"""Run metadata, and the output directory a run owns."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

# PIP_LOG_NAME is the container side of the same file; imported rather than
# repeated so the two cannot drift apart.
from egresslens.docker_runner import PIP_LOG_NAME

# Artifacts the container creates inside the output directory once it is
# bind-mounted at /output: the traced command's two streams and pip's log by
# shell redirection, the trace by strace -o.
CONTAINER_WRITTEN_ARTIFACTS = (
    "cmd_stdout",
    "cmd_stderr",
    PIP_LOG_NAME,
    "egress.strace",
)

# Artifacts this process writes on the host, after the container has exited.
HOST_WRITTEN_ARTIFACTS = (
    "egress.jsonl",
    "run.json",
)

# Every file a capture writes into its output directory.
RUN_ARTIFACT_NAMES = CONTAINER_WRITTEN_ARTIFACTS + HOST_WRITTEN_ARTIFACTS


def clear_run_artifacts(output_dir: Path) -> None:
    """Clear the artifacts of any earlier run from an output directory.

    The directory has to describe the run that just happened. Without this, a run
    that produces fewer files than the last one -- or none at all, when a
    dependency install fails before the app starts -- leaves the previous run's
    report in place, where a reader or a CI gate reads it as this run's result.

    The container-written ones are TRUNCATED, not removed, and that is not a
    stylistic choice. This directory is about to be bind-mounted at /output, and
    on Docker Desktop's shared filesystem deleting a file here leaves the guest
    unable to re-create it: the redirection fails with "cannot create
    /output/cmd_stderr: Directory nonexistent", sh exits 2, and the traced
    command never runs -- measured on 7 of 12 repeat runs, with the empty capture
    then reported as a quiet run. Truncating keeps the dentry the guest reopens
    and still leaves no stale content behind.

    Only the names above are touched, never a glob: --out is a user-supplied path
    that may well hold files this tool did not write.
    """
    for name in CONTAINER_WRITTEN_ARTIFACTS:
        artifact = output_dir / name
        if artifact.is_file():
            with open(artifact, "wb"):
                pass

    # Removed rather than truncated, so "no report" is the absence of a report
    # and not a zero-byte one that a reader has to interpret.
    for name in HOST_WRITTEN_ARTIFACTS:
        artifact = output_dir / name
        if artifact.is_file():
            artifact.unlink()


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
    ipv6_connects_skipped: int = 0,
    udp_probes_skipped: int = 0,
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
        ipv6_connects_skipped: AF_INET6 connect() attempts that were observed but
            not captured (IPv4 only)
        udp_probes_skipped: UDP connect() calls excluded because nothing was ever
            sent on the socket, so no packet reached the address (see
            strace_parser.is_silent_udp_connect). Reported rather than dropped
            silently: the number is the difference between what the trace shows
            and what the report claims.

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
            "ipv6_connects_skipped": ipv6_connects_skipped,
            "udp_probes_skipped": udp_probes_skipped,
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
