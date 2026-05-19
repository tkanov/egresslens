#!/usr/bin/env python3
"""Simple test script for strace parser."""

import json
import tempfile
from pathlib import Path

from egresslens.strace_parser import (
    parse_resumed_connect_line,
    parse_socket_line,
    parse_strace_line,
    parse_to_jsonl,
    parse_unfinished_connect_line,
)


def test_parse_strace_line():
    """Test parsing individual strace lines."""
    # Test successful connection
    line1 = '12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.69")}, 16) = 0'
    event1 = parse_strace_line(line1)
    assert event1 is not None
    assert event1["pid"] == 12345
    assert event1["ts"] == 1707150823.512
    assert event1["dst_ip"] == "151.101.1.69"
    assert event1["dst_port"] == 443
    assert event1["proto"] == "unknown"
    assert event1["result"] == "ok"
    assert event1["errno"] is None
    print("✓ Successfully parsed successful connection")

    # Test failed connection
    line2 = '12346 1707150824.123 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.1.1")}, 16) = -1 ECONNREFUSED'
    event2 = parse_strace_line(line2)
    assert event2 is not None
    assert event2["pid"] == 12346
    assert event2["dst_ip"] == "192.168.1.1"
    assert event2["dst_port"] == 80
    assert event2["proto"] == "unknown"
    assert event2["result"] == "error"
    assert event2["errno"] == "ECONNREFUSED"
    print("✓ Successfully parsed failed connection")

    # Test non-matching line
    line3 = "12347 1707150825.456 openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3"
    event3 = parse_strace_line(line3)
    assert event3 is None
    print("✓ Correctly ignored non-connect line")

    # Test IPv6 (should be ignored for MVP)
    line4 = '12348 1707150826.789 connect(5, {sa_family=AF_INET6, ...}, 28) = 0'
    event4 = parse_strace_line(line4)
    assert event4 is None
    print("✓ Correctly ignored IPv6 connection")


def test_parse_socket_line():
    """Test parsing socket() lines for protocol tracking."""
    tcp_line = "12345 1707150823.500 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3"
    tcp_socket = parse_socket_line(tcp_line)
    assert tcp_socket == (12345, 3, "tcp")
    print("✓ Successfully parsed TCP socket")

    udp_line = "12345 1707150823.501 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 4"
    udp_socket = parse_socket_line(udp_line)
    assert udp_socket == (12345, 4, "udp")
    print("✓ Successfully parsed UDP socket")

    failed_line = "12345 1707150823.502 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = -1 EMFILE"
    failed_socket = parse_socket_line(failed_line)
    assert failed_socket is None
    print("✓ Correctly ignored failed socket")


def test_parse_split_connect_line():
    """Test parsing strace connect() lines split as unfinished/resumed."""
    socket_state = {(12345, 4): "udp"}
    unfinished_line = '12345 1707150823.512 connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16 <unfinished ...>'
    unfinished = parse_unfinished_connect_line(unfinished_line, socket_state)
    assert unfinished is not None
    pid, pending_event = unfinished
    assert pid == 12345
    assert pending_event["dst_ip"] == "8.8.8.8"
    assert pending_event["dst_port"] == 53
    assert pending_event["proto"] == "udp"

    resumed_line = "12345 1707150823.513 <... connect resumed>) = 0"
    resumed = parse_resumed_connect_line(resumed_line)
    assert resumed == (12345, 0, None)
    print("✓ Successfully parsed split connect")


def test_parse_to_jsonl():
    """Test parsing full file to JSONL."""
    # Create sample strace output
    strace_content = """12345 1707150823.500 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.69")}, 16) = 0
12346 1707150824.100 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
12346 1707150824.123 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.1.1")}, 16) = -1 ECONNREFUSED
12347 1707150825.456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
12348 1707150826.700 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 5
12348 1707150826.789 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0
12349 1707150827.700 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 6
12349 1707150827.789 connect(6, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("127.0.0.1")}, 16 <unfinished ...>
12349 1707150827.790 <... connect resumed>) = 0
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"

        strace_file.write_text(strace_content)

        count = parse_to_jsonl(strace_file, jsonl_file)
        assert count == 4, f"Expected 4 events, got {count}"

        # Verify JSONL content
        lines = jsonl_file.read_text().strip().split("\n")
        assert len(lines) == 4

        event1 = json.loads(lines[0])
        assert event1["dst_ip"] == "151.101.1.69"
        assert event1["dst_port"] == 443
        assert event1["proto"] == "tcp"

        event3 = json.loads(lines[2])
        assert event3["dst_ip"] == "8.8.8.8"
        assert event3["dst_port"] == 53
        assert event3["proto"] == "udp"

        event4 = json.loads(lines[3])
        assert event4["dst_ip"] == "127.0.0.1"
        assert event4["dst_port"] == 9
        assert event4["proto"] == "udp"
        assert event4["result"] == "ok"

        print("✓ Successfully parsed file to JSONL")


if __name__ == "__main__":
    print("Testing strace parser...")
    test_parse_strace_line()
    test_parse_socket_line()
    test_parse_split_connect_line()
    test_parse_to_jsonl()
    print("\nAll tests passed! ✓")
