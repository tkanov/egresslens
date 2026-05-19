"""Parser for strace output to extract network connection events."""

import json
import re
from pathlib import Path
from typing import Iterator, Optional


SocketState = dict[tuple[int, int], str]
PendingConnectState = dict[int, dict]


def parse_socket_line(line: str) -> Optional[tuple[int, int, str]]:
    """Parse a socket() syscall and return PID, file descriptor, and protocol."""
    if "socket(" not in line or "AF_INET" not in line:
        return None

    # Example:
    # 12345 1707150823.500 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
    pattern = (
        r"(\d+)\s+[\d.]+\s+socket\("
        r"\s*AF_INET\s*,\s*([^,]+)\s*,\s*([^)]+)\)\s*=\s*(-?\d+)"
    )
    match = re.search(pattern, line)
    if not match:
        return None

    fd = int(match.group(4))
    if fd < 0:
        return None

    pid = int(match.group(1))
    socket_type = match.group(2)
    protocol = match.group(3)
    proto = protocol_from_socket(socket_type, protocol)
    return pid, fd, proto


def protocol_from_socket(socket_type: str, protocol: str) -> str:
    """Map socket() type/protocol fields to a transport protocol label."""
    socket_type = socket_type.upper()
    protocol = protocol.upper()

    if "IPPROTO_TCP" in protocol or "SOCK_STREAM" in socket_type:
        return "tcp"
    if "IPPROTO_UDP" in protocol or "SOCK_DGRAM" in socket_type:
        return "udp"
    if "SOCK_RAW" in socket_type:
        return "raw"
    return "unknown"


def parse_strace_file(strace_path: Path) -> Iterator[dict]:
    """Parse strace output file and yield connection events.

    Args:
        strace_path: Path to strace output file

    Yields:
        Event dictionaries matching the JSONL schema
    """
    socket_state: SocketState = {}
    pending_connects: PendingConnectState = {}

    with open(strace_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            socket_info = parse_socket_line(line)
            if socket_info:
                pid, fd, proto = socket_info
                socket_state[(pid, fd)] = proto

            pending_connect = parse_unfinished_connect_line(line, socket_state)
            if pending_connect:
                pid, event = pending_connect
                pending_connects[pid] = event
                continue

            resumed_connect = parse_resumed_connect_line(line)
            if resumed_connect:
                pid, result_code, errno = resumed_connect
                event = pending_connects.pop(pid, None)
                if event:
                    event["result"] = "ok" if result_code == 0 else "error"
                    event["errno"] = errno
                    yield event
                continue

            event = parse_strace_line(line, socket_state)
            if event:
                yield event


def build_connect_event(
    pid: int,
    timestamp: float,
    fd: int,
    dst_port: int,
    dst_ip: str,
    socket_state: Optional[SocketState] = None,
) -> dict:
    """Build a connection event with protocol from socket state when available."""
    proto = "unknown"
    if socket_state:
        proto = socket_state.get((pid, fd), "unknown")

    return {
        "ts": timestamp,
        "pid": pid,
        "event": "connect",
        "family": "inet",
        "proto": proto,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }


def parse_strace_line(line: str, socket_state: Optional[SocketState] = None) -> Optional[dict]:
    """Parse a single strace line for connect() syscalls.

    Args:
        line: Single line from strace output
        socket_state: Optional mapping of (pid, fd) to protocol from socket() syscalls

    Returns:
        Event dictionary or None if line doesn't match
    """
    # Filter for AF_INET only (IPv6/AF_INET6 not supported in current MVP - see docs/getting-started.md#limitations)
    if "connect(" not in line or "sa_family=AF_INET" not in line:
        return None

    # Pattern: PID timestamp connect(fd, sockaddr, addrlen) = result [errno]
    # Example: 12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
    pattern = r"(\d+)\s+([\d.]+)\s+connect\((\d+),\s*\{[^}]*sa_family=AF_INET[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\(\"([^\"]+)\"\)[^}]*\}[^)]*\)\s*=\s*(-?\d+)(?:\s+(\w+))?"

    match = re.search(pattern, line)
    if not match:
        return None

    pid = int(match.group(1))
    timestamp = float(match.group(2))
    fd = int(match.group(3))
    dst_port = int(match.group(4))
    dst_ip = match.group(5)
    result_code = int(match.group(6))
    errno = match.group(7) if match.group(7) else None

    event = build_connect_event(pid, timestamp, fd, dst_port, dst_ip, socket_state)
    event["result"] = "ok" if result_code == 0 else "error"
    event["errno"] = errno
    return event


def parse_unfinished_connect_line(
    line: str,
    socket_state: Optional[SocketState] = None,
) -> Optional[tuple[int, dict]]:
    """Parse a connect() line split by strace as unfinished."""
    if "connect(" not in line or "<unfinished ...>" not in line or "sa_family=AF_INET" not in line:
        return None

    # Example:
    # 12345 1707150823.512 connect(3, {sa_family=AF_INET, ...}, 16 <unfinished ...>
    pattern = r"(\d+)\s+([\d.]+)\s+connect\((\d+),\s*\{[^}]*sa_family=AF_INET[^}]*sin_port=htons\((\d+)\)[^}]*sin_addr=inet_addr\(\"([^\"]+)\"\)[^}]*\}[^<]*<unfinished \.\.\.>"

    match = re.search(pattern, line)
    if not match:
        return None

    pid = int(match.group(1))
    timestamp = float(match.group(2))
    fd = int(match.group(3))
    dst_port = int(match.group(4))
    dst_ip = match.group(5)

    event = build_connect_event(pid, timestamp, fd, dst_port, dst_ip, socket_state)
    return pid, event


def parse_resumed_connect_line(line: str) -> Optional[tuple[int, int, Optional[str]]]:
    """Parse a strace line that resumes a previously unfinished connect()."""
    if "<... connect resumed>" not in line:
        return None

    # Example:
    # 12345 1707150823.513 <... connect resumed>) = 0
    pattern = r"(\d+)\s+[\d.]+\s+<\.\.\. connect resumed>\)\s+=\s+(-?\d+)(?:\s+(\w+))?"
    match = re.search(pattern, line)
    if not match:
        return None

    pid = int(match.group(1))
    result_code = int(match.group(2))
    errno = match.group(3) if match.group(3) else None
    return pid, result_code, errno


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
