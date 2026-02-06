"""Parser for strace output to extract network connection events."""

import json
import re
from pathlib import Path
from typing import Iterator, Optional


def parse_strace_file(strace_path: Path) -> Iterator[dict]:
    """Parse strace output file and yield connection events.

    Args:
        strace_path: Path to strace output file

    Yields:
        Event dictionaries matching the JSONL schema
    """
    with open(strace_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_strace_line(line)
            if event:
                yield event


def parse_strace_line(line: str) -> Optional[dict]:
    """Parse a single strace line for connect() syscalls.

    Args:
        line: Single line from strace output

    Returns:
        Event dictionary or None if line doesn't match
    """
    # Match lines with connect( and AF_INET (skip IPv6 for MVP)
    if "connect(" not in line or "AF_INET" not in line:
        return None

    # Pattern: PID timestamp connect(...) = result [errno]
    # Example: 12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
    pattern = r"(\d+)\s+([\d.]+)\s+connect\([^,]+,\s*\{[^}]*sa_family=AF_INET[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\(\"([^\"]+)\"\)[^}]*\}[^)]*\)\s*=\s*(-?\d+)(?:\s+(\w+))?"

    match = re.search(pattern, line)
    if not match:
        return None

    pid = int(match.group(1))
    timestamp = float(match.group(2))
    dst_port = int(match.group(3))
    dst_ip = match.group(4)
    result_code = int(match.group(5))
    errno = match.group(6) if match.group(6) else None

    return {
        "ts": timestamp,
        "pid": pid,
        "event": "connect",
        "family": "inet",
        "proto": "tcp",
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "result": "ok" if result_code == 0 else "error",
        "errno": errno,
    }


def parse_to_jsonl(strace_path: Path, output_path: Path) -> int:
    """Parse strace file and write JSONL output.

    Args:
        strace_path: Path to strace output file
        output_path: Path to write JSONL output

    Returns:
        Number of events parsed
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        for event in parse_strace_file(strace_path):
            f.write(json.dumps(event) + "\n")
            count += 1

    return count
