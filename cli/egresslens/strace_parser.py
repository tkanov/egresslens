"""Parser for strace output to extract outbound network events.

Two kinds of syscall name an egress destination: connect(), and the send*
family when the socket is unconnected. Both are parsed here so a report covers
datagram egress that never calls connect().
"""

import json
import re
from pathlib import Path
from typing import Iterator, Optional


SocketState = dict[tuple[int, int], str]
PendingSocketState = dict[int, str]
PendingConnectState = dict[int, dict]
PendingSendState = dict[int, list]

# Syscalls in strace's `network` class that carry an explicit destination
# sockaddr. connect() covers the connection-oriented case; the send* family
# names its destination per-call whenever the socket is unconnected, which is how
# a lot of real UDP egress leaves a process -- dnspython resolves via sendto()
# and never calls connect(), and statsd, syslog-over-UDP, NTP and QUIC stacks
# behave the same way. Parsing connect() alone made that egress invisible in
# egress.jsonl even though the addresses were sitting in egress.strace.
SEND_SYSCALLS = ("sendto", "sendmsg", "sendmmsg")

_SEND_SYSCALL_RE = re.compile(
    r"(\d+)\s+([\d.]+)\s+(" + "|".join(SEND_SYSCALLS) + r")\((\d+)"
)

# One AF_INET sockaddr. Restricted to the innermost brace group ([^{}]) so the
# msg_name={...} nested inside sendmsg's msghdr matches without swallowing the
# structure around it, and so sendmmsg's array yields one match per message.
# The trailing comma after AF_INET is what keeps this from also matching AF_INET6.
_SOCKADDR_IN_RE = re.compile(
    r"\{[^{}]*sa_family=AF_INET,[^{}]*sin_port=htons\((\d+)\)[^{}]*"
    r"sin_addr=inet_addr\(\"([^\"]+)\"\)[^{}]*\}"
)

# Trailing return value of a completed call, tolerant of strace's errno
# description:  ) = 29  |  ) = -1 EPERM  |  ) = -1 EPERM (Operation not permitted)
#
# Anchored at end of line AND required to follow the syscall's closing paren.
# Both halves matter. Anchoring stops a `= 0` early in a captured payload from
# being read as the result; requiring the paren stops a payload that *ends* the
# line from doing the same. That second case is reachable: sendmsg prints
# msg_name before msg_iov, so a trace truncated mid-payload -- a killed
# container, or the `&& sync` in docker_runner being skipped because the traced
# app exited non-zero -- leaves a valid sockaddr with payload text at the line
# end. Such a line yields no event rather than an event with a fabricated result.
_SEND_RESULT_RE = re.compile(
    r"\)\s*=\s*(-?\d+)(?:\s+([A-Z][A-Z0-9_]*))?(?:\s+\([^)]*\))?\s*$"
)

_RESUMED_SEND_RE = re.compile(
    r"(\d+)\s+[\d.]+\s+<\.\.\. (?:" + "|".join(SEND_SYSCALLS) + r") resumed>"
)

# socket() split across two lines, which `strace -f` does whenever another
# thread's event lands between syscall entry and exit. Unlike connect() and
# send*(), neither half is usable alone: the arguments naming the protocol are
# decoded on entry, but the fd they belong to is the return value and only shows
# up on the resumed line. Dropping such a pair leaves the fd absent from
# SocketState, and every connect() on it is then labelled proto "unknown" --
# silently understating a report as no-protocol-known rather than tcp or udp.
#
# The type argument is matched without `<` so a socket() whose third argument is
# missing cannot swallow the `<unfinished ...>` marker itself.
_UNFINISHED_SOCKET_RE = re.compile(
    r"(\d+)\s+[\d.]+\s+socket\(\s*AF_INET\s*,\s*([^,<]+?)\s*"
    r"(?:,\s*([^<]*?))?\s*<unfinished \.\.\.>"
)

_RESUMED_SOCKET_RE = re.compile(r"(\d+)\s+[\d.]+\s+<\.\.\. socket resumed>\)?\s*=\s*(-?\d+)")


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


def parse_unfinished_socket_line(line: str) -> Optional[tuple[int, str]]:
    """Parse a socket() line split by strace as unfinished.

    Returns the PID and protocol only. The file descriptor is socket()'s return
    value, so it is not on this line -- it arrives on the matching resumed line,
    and the two have to be joined to know which fd the protocol describes.
    """
    match = _UNFINISHED_SOCKET_RE.search(line)
    if not match:
        return None

    pid = int(match.group(1))
    socket_type = match.group(2)
    # Absent when strace split the line before the protocol argument; the socket
    # type alone still distinguishes SOCK_STREAM from SOCK_DGRAM.
    protocol = match.group(3) or ""
    return pid, protocol_from_socket(socket_type, protocol)


def parse_resumed_socket_line(line: str) -> Optional[tuple[int, int]]:
    """Parse a strace line that resumes a previously unfinished socket().

    Returns the PID and the returned file descriptor, which is negative when the
    call failed.
    """
    match = _RESUMED_SOCKET_RE.search(line)
    if not match:
        return None

    pid = int(match.group(1))
    fd = int(match.group(2))
    return pid, fd


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


def is_ipv6_connect_line(line: str) -> bool:
    """Return True for a connect() to an AF_INET6 address.

    IPv6 destinations are not captured (see docs/getting-started.md#limitations),
    but they are counted so reports do not silently understate egress.
    """
    return "connect(" in line and "sa_family=AF_INET6" in line


def parse_strace_file(strace_path: Path, stats: Optional[dict] = None) -> Iterator[dict]:
    """Parse strace output file and yield egress events.

    Covers connect() plus the send* syscalls that carry their own destination
    sockaddr, so egress over unconnected UDP is reported rather than dropped.

    Args:
        strace_path: Path to strace output file
        stats: Optional dict populated with parse counters once the file is fully
            consumed. Currently records ``ipv6_connects_skipped`` (AF_INET6
            connect() attempts that were counted but not captured).

    Yields:
        Event dictionaries matching the JSONL schema
    """
    socket_state: SocketState = {}
    pending_sockets: PendingSocketState = {}
    pending_connects: PendingConnectState = {}
    pending_sends: PendingSendState = {}
    ipv6_connects_skipped = 0

    with open(strace_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if is_ipv6_connect_line(line):
                ipv6_connects_skipped += 1

            socket_info = parse_socket_line(line)
            if socket_info:
                pid, fd, proto = socket_info
                socket_state[(pid, fd)] = proto

            pending_socket = parse_unfinished_socket_line(line)
            if pending_socket:
                pid, proto = pending_socket
                # Keyed by PID because strace's first column is a TID, and a
                # thread can only be inside one syscall at a time.
                pending_sockets[pid] = proto
                continue

            resumed_socket = parse_resumed_socket_line(line)
            if resumed_socket:
                pid, fd = resumed_socket
                proto = pending_sockets.pop(pid, None)
                # A failed socket() returns no fd to attribute the protocol to,
                # matching parse_socket_line's handling of the unsplit case.
                if proto is not None and fd >= 0:
                    socket_state[(pid, fd)] = proto
                continue

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

            pending_send = parse_unfinished_send_line(line, socket_state)
            if pending_send:
                pid, send_events = pending_send
                pending_sends[pid] = send_events
                continue

            resumed_send = parse_resumed_send_line(line)
            if resumed_send:
                pid, result_code, errno = resumed_send
                send_events = pending_sends.pop(pid, None)
                for event in send_events or []:
                    event["result"] = "ok" if result_code >= 0 else "error"
                    event["errno"] = errno
                    yield event
                continue

            parsed_send = parse_send_line(line, socket_state)
            if parsed_send:
                for event in parsed_send[1]:
                    yield event
                continue

            event = parse_strace_line(line, socket_state)
            if event:
                yield event

    if stats is not None:
        stats["ipv6_connects_skipped"] = ipv6_connects_skipped


def build_connect_event(
    pid: int,
    timestamp: float,
    fd: int,
    dst_port: int,
    dst_ip: str,
    socket_state: Optional[SocketState] = None,
    event: str = "connect",
) -> dict:
    """Build an egress event with protocol from socket state when available.

    ``event`` records which syscall named the destination -- ``connect`` for the
    connection-oriented path, or the send* syscall name for a datagram whose
    address was supplied per-call.
    """
    proto = "unknown"
    if socket_state:
        proto = socket_state.get((pid, fd), "unknown")

    return {
        "ts": timestamp,
        "pid": pid,
        "event": event,
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


def _send_destinations(
    line: str,
    socket_state: Optional[SocketState] = None,
) -> Optional[tuple[int, list]]:
    """Build an event for every AF_INET destination named on a send*() line.

    sendto() names one destination, sendmsg() names one via ``msg_name``, and
    sendmmsg() names one per message in its array -- hence a list. A send on a
    *connected* socket prints ``NULL`` for the address and yields nothing here,
    which is correct: that traffic is already reported via the socket's
    connect() event, so there is no double counting.
    """
    match = _SEND_SYSCALL_RE.search(line)
    if not match:
        return None

    pid = int(match.group(1))
    timestamp = float(match.group(2))
    syscall = match.group(3)
    fd = int(match.group(4))

    events = [
        build_connect_event(
            pid, timestamp, fd, int(port), ip, socket_state, event=syscall
        )
        for port, ip in _SOCKADDR_IN_RE.findall(line)
    ]
    if not events:
        return None
    return pid, events


def parse_send_line(
    line: str,
    socket_state: Optional[SocketState] = None,
) -> Optional[tuple[int, list]]:
    """Parse a completed send*() syscall that named its own destination."""
    if "<unfinished ...>" in line:
        return None

    result_match = _SEND_RESULT_RE.search(line)
    if not result_match:
        return None

    parsed = _send_destinations(line, socket_state)
    if not parsed:
        return None

    pid, events = parsed
    result_code = int(result_match.group(1))
    errno = result_match.group(2)
    for event in events:
        # send* returns the byte/message count on success, not 0 like connect().
        event["result"] = "ok" if result_code >= 0 else "error"
        event["errno"] = errno
    return pid, events


def parse_unfinished_send_line(
    line: str,
    socket_state: Optional[SocketState] = None,
) -> Optional[tuple[int, list]]:
    """Parse a send*() line split by strace as unfinished.

    strace decodes the arguments on syscall entry, so the destination is present
    on this line; only the result has to wait for the matching resumed line.
    """
    if "<unfinished ...>" not in line:
        return None
    return _send_destinations(line, socket_state)


def parse_resumed_send_line(line: str) -> Optional[tuple[int, int, Optional[str]]]:
    """Parse a strace line that resumes a previously unfinished send*()."""
    match = _RESUMED_SEND_RE.search(line)
    if not match:
        return None

    result_match = _SEND_RESULT_RE.search(line)
    if not result_match:
        return None

    pid = int(match.group(1))
    result_code = int(result_match.group(1))
    errno = result_match.group(2)
    return pid, result_code, errno


def parse_to_jsonl(strace_path: Path, output_path: Path, stats: Optional[dict] = None) -> int:
    """Parse strace file and write JSONL output.

    Args:
        strace_path: Path to strace output file
        output_path: Path to write JSONL output
        stats: Optional dict populated with parse counters (e.g.
            ``ipv6_connects_skipped``) after the file is fully parsed.

    Returns:
        Number of events parsed
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        for event in parse_strace_file(strace_path, stats):
            f.write(json.dumps(event) + "\n")
            count += 1

    return count
