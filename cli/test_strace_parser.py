#!/usr/bin/env python3
"""Simple test script for strace parser."""

import json
import tempfile
from pathlib import Path

from egresslens.strace_parser import parse_strace_line, parse_to_jsonl


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


def test_parse_to_jsonl():
    """Test parsing full file to JSONL."""
    # Create sample strace output
    strace_content = """12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.69")}, 16) = 0
12346 1707150824.123 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.1.1")}, 16) = -1 ECONNREFUSED
12347 1707150825.456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
12348 1707150826.789 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"

        strace_file.write_text(strace_content)

        count = parse_to_jsonl(strace_file, jsonl_file)
        assert count == 3, f"Expected 3 events, got {count}"

        # Verify JSONL content
        lines = jsonl_file.read_text().strip().split("\n")
        assert len(lines) == 3

        event1 = json.loads(lines[0])
        assert event1["dst_ip"] == "151.101.1.69"
        assert event1["dst_port"] == 443

        print("✓ Successfully parsed file to JSONL")


if __name__ == "__main__":
    print("Testing strace parser...")
    test_parse_strace_line()
    test_parse_to_jsonl()
    print("\nAll tests passed! ✓")
