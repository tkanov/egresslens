#!/usr/bin/env python3
"""Simple test script for strace parser."""

import json
import tempfile
from pathlib import Path

from egresslens.strace_parser import (
    is_ipv6_connect_line,
    parse_resumed_connect_line,
    parse_resumed_send_line,
    parse_resumed_socket_line,
    parse_send_line,
    parse_socket_line,
    parse_strace_line,
    parse_to_jsonl,
    parse_unfinished_connect_line,
    parse_unfinished_send_line,
    parse_unfinished_socket_line,
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


def test_parse_split_socket_line():
    """Test parsing socket() lines split as unfinished/resumed."""
    unfinished_line = (
        "2748 1785413866.874733 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, "
        "IPPROTO_IP <unfinished ...>"
    )
    assert parse_unfinished_socket_line(unfinished_line) == (2748, "tcp")

    # The entry half carries no fd, so on its own it must not reach SocketState.
    assert parse_socket_line(unfinished_line) is None

    resumed_line = "2748 1785413866.874780 <... socket resumed>) = 4"
    assert parse_resumed_socket_line(resumed_line) == (2748, 4)

    dgram_line = "2748 1785413866.875596 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC <unfinished ...>"
    assert parse_unfinished_socket_line(dgram_line) == (2748, "udp")

    failed_resumed = "2748 1785413866.875600 <... socket resumed>) = -1 EMFILE"
    assert parse_resumed_socket_line(failed_resumed) == (2748, -1)

    # socketpair() is a different syscall and must not be read as a socket().
    assert parse_resumed_socket_line("2748 1785413866.8756 <... socketpair resumed>) = 0") is None
    print("✓ Successfully parsed split socket")


def test_split_socket_keeps_protocol_attribution():
    """A socket() split across two lines still labels the connect() on its fd.

    Reproduces the interleaving that `strace -f` produces when another thread's
    event lands between socket() entry and exit. Before the resumed half was
    joined to the entry half, the fd never reached SocketState and this connect()
    came out as proto "unknown" -- which made the real-strace integration test
    fail on roughly one CI run in four, depending on thread scheduling.
    """
    strace_content = """2748 1785413866.860043 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
2748 1785413866.874733 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP <unfinished ...>
2749 1785413866.874750 accept4(3, <unfinished ...>
2748 1785413866.874780 <... socket resumed>) = 4
2748 1785413866.874810 connect(4, {sa_family=AF_INET, sin_port=htons(57407), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
2748 1785413866.875596 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
2748 1785413866.875660 connect(3, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
2748 1785413866.875700 sendto(3, "x", 1, MSG_NOSIGNAL, NULL, 0) = 1
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"

        strace_file.write_text(strace_content)

        count = parse_to_jsonl(strace_file, jsonl_file)
        assert count == 2, f"Expected 2 events, got {count}"

        events = [json.loads(line) for line in jsonl_file.read_text().strip().split("\n")]

        tcp_event = events[0]
        assert tcp_event["dst_port"] == 57407
        assert tcp_event["proto"] == "tcp", "split socket() lost its protocol"
        assert tcp_event["result"] == "ok"

        # fd 3 is reused by the later SOCK_DGRAM socket, so the same fd must now
        # read as udp rather than keeping the first socket's tcp label.
        udp_event = events[1]
        assert udp_event["dst_port"] == 9
        assert udp_event["proto"] == "udp"
    print("✓ Split socket() keeps protocol attribution")


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
12348 1707150826.790 sendto(5, "\\1\\0", 2, MSG_NOSIGNAL, NULL, 0) = 2
12349 1707150827.700 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 6
12349 1707150827.789 connect(6, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("127.0.0.1")}, 16 <unfinished ...>
12349 1707150827.790 <... connect resumed>) = 0
12349 1707150827.800 sendto(6, "\\1\\0", 2, MSG_NOSIGNAL, NULL, 0) = 2
"""
    # The two sendto lines are what make these connected UDP sockets egress: a
    # UDP connect() on its own transmits nothing, and one that is never followed
    # by traffic is dropped as an address-selection probe (see
    # test_udp_connect_without_traffic_is_not_reported_as_egress).

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


def test_ipv6_connects_counted_not_captured():
    """IPv6 connect() attempts are not emitted as events but are counted."""
    assert is_ipv6_connect_line(
        '111 1.0 connect(5, {sa_family=AF_INET6, sin6_port=htons(443)}, 28) = 0'
    )
    assert not is_ipv6_connect_line(
        '111 1.0 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0'
    )
    assert not is_ipv6_connect_line("111 1.0 socket(AF_INET6, SOCK_STREAM, 0) = 5")

    strace_content = """12345 1707150823.500 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
12345 1707150823.512 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.69")}, 16) = 0
12346 1707150824.100 connect(4, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")}, 28) = 0
12347 1707150825.100 connect(5, {sa_family=AF_INET6, sin6_port=htons(80), sin6_addr=inet_pton(AF_INET6, "2001:4860:4860::8888")}, 28 <unfinished ...>
12347 1707150825.101 <... connect resumed>) = 0
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"
        strace_file.write_text(strace_content)

        stats: dict = {}
        count = parse_to_jsonl(strace_file, jsonl_file, stats)

        # Only the single IPv4 connect is emitted.
        assert count == 1, f"Expected 1 event, got {count}"
        # Both IPv6 connects counted exactly once each (unfinished counted once).
        assert stats["ipv6_connects_skipped"] == 2, stats

        lines = jsonl_file.read_text().strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0])["dst_ip"] == "151.101.1.69"

    print("✓ IPv6 connects counted but not captured")


def test_parse_sendto_line():
    """sendto() on an unconnected socket names its own destination."""
    socket_state = {(12348, 5): "udp"}
    line = (
        '12348 1707150826.789 sendto(5, "\\253\\17\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0'
        '\\7example\\3com\\0\\0\\1\\0\\1", 29, 0, {sa_family=AF_INET, '
        'sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 29'
    )
    parsed = parse_send_line(line, socket_state)
    assert parsed is not None
    pid, events = parsed
    assert pid == 12348
    assert len(events) == 1
    assert events[0]["dst_ip"] == "8.8.8.8"
    assert events[0]["dst_port"] == 53
    assert events[0]["proto"] == "udp"
    assert events[0]["event"] == "sendto"
    assert events[0]["result"] == "ok"
    assert events[0]["errno"] is None
    print("✓ Successfully parsed unconnected sendto")

    # A send on a connected socket prints NULL: already covered by its connect().
    connected = '12348 1707150826.800 sendto(6, "hello", 5, 0, NULL, 0) = 5'
    assert parse_send_line(connected, socket_state) is None
    print("✓ Correctly ignored sendto on a connected socket")

    # IPv6 destinations stay uncaptured, exactly as for connect().
    ipv6 = (
        '12348 1707150826.900 sendto(7, "x", 1, 0, {sa_family=AF_INET6, '
        'sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, '
        '"2606:2800:220:1:248:1893:25c8:1946", &sin6_addr), sin6_scope_id=0}, 28) = 1'
    )
    assert parse_send_line(ipv6, socket_state) is None
    print("✓ Correctly ignored IPv6 sendto")


def test_parse_sendmsg_line():
    """sendmsg() names its destination via msg_name."""
    line = (
        '12349 1707150827.100 sendmsg(7, {msg_name={sa_family=AF_INET, '
        'sin_port=htons(8125), sin_addr=inet_addr("198.51.100.44")}, '
        'msg_namelen=16, msg_iov=[{iov_base="egress.test:1|c", iov_len=15}], '
        "msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 15"
    )
    parsed = parse_send_line(line, {(12349, 7): "udp"})
    assert parsed is not None
    _, events = parsed
    assert len(events) == 1
    assert events[0]["dst_ip"] == "198.51.100.44"
    assert events[0]["dst_port"] == 8125
    assert events[0]["event"] == "sendmsg"
    print("✓ Successfully parsed sendmsg msg_name")

    null_name = (
        "12349 1707150827.200 sendmsg(8, {msg_name=NULL, msg_namelen=0, "
        'msg_iov=[{iov_base="x", iov_len=1}], msg_iovlen=1, msg_controllen=0, '
        "msg_flags=0}, 0) = 1"
    )
    assert parse_send_line(null_name, None) is None
    print("✓ Correctly ignored sendmsg with msg_name=NULL")


def test_parse_sendmmsg_line():
    """sendmmsg() carries one destination per message in its array."""
    line = (
        "12350 1707150828.100 sendmmsg(9, [{msg_hdr={msg_name={sa_family=AF_INET, "
        'sin_port=htons(53), sin_addr=inet_addr("1.1.1.1")}, msg_namelen=16, '
        'msg_iov=[{iov_base="q1", iov_len=2}], msg_iovlen=1, msg_controllen=0, '
        "msg_flags=0}, msg_len=2}, {msg_hdr={msg_name={sa_family=AF_INET, "
        'sin_port=htons(53), sin_addr=inet_addr("1.0.0.1")}, msg_namelen=16, '
        'msg_iov=[{iov_base="q2", iov_len=2}], msg_iovlen=1, msg_controllen=0, '
        "msg_flags=0}, msg_len=2}], 2, 0) = 2"
    )
    parsed = parse_send_line(line, {(12350, 9): "udp"})
    assert parsed is not None
    _, events = parsed
    assert len(events) == 2, f"Expected 2 events, got {len(events)}"
    assert [e["dst_ip"] for e in events] == ["1.1.1.1", "1.0.0.1"]
    assert all(e["dst_port"] == 53 for e in events)
    assert all(e["event"] == "sendmmsg" for e in events)
    print("✓ Successfully parsed both sendmmsg destinations")


def test_parse_failed_send_line():
    """A rejected send is reported as an error, with strace's errno description."""
    line = (
        '12351 1707150829.100 sendto(10, "x", 1, 0, {sa_family=AF_INET, '
        'sin_port=htons(443), sin_addr=inet_addr("203.0.113.7")}, 16) '
        "= -1 EPERM (Operation not permitted)"
    )
    parsed = parse_send_line(line, None)
    assert parsed is not None
    _, events = parsed
    assert events[0]["dst_ip"] == "203.0.113.7"
    assert events[0]["result"] == "error"
    assert events[0]["errno"] == "EPERM"
    print("✓ Successfully parsed failed send with errno")


def test_parse_split_send_line():
    """Test parsing send*() lines split as unfinished/resumed."""
    unfinished = (
        '12352 1707150830.100 sendto(11, "x", 1, 0, {sa_family=AF_INET, '
        'sin_port=htons(123), sin_addr=inet_addr("203.0.113.9")}, 16 <unfinished ...>'
    )
    pending = parse_unfinished_send_line(unfinished, {(12352, 11): "udp"})
    assert pending is not None
    pid, events = pending
    assert pid == 12352
    assert len(events) == 1
    assert events[0]["dst_ip"] == "203.0.113.9"
    assert events[0]["dst_port"] == 123
    # No result until the resumed line arrives.
    assert "result" not in events[0]

    # The same line must not be treated as a completed call.
    assert parse_send_line(unfinished, None) is None

    resumed = "12352 1707150830.101 <... sendto resumed>) = 1"
    assert parse_resumed_send_line(resumed) == (12352, 1, None)
    print("✓ Successfully parsed split send")


def test_truncated_send_line_is_not_given_a_fabricated_result():
    """A line cut off mid-payload must not borrow a result from the payload text.

    sendmsg prints msg_name before msg_iov, so a trace truncated mid-payload
    still carries a valid sockaddr. That is reachable in practice: the container
    may be killed, and docker_runner's `strace ... && sync` skips the sync
    whenever the traced app exits non-zero. Requiring the return value to follow
    the syscall's closing paren keeps `metric=0` from being read as `= 0`.
    """
    truncated = (
        '12345 1.0 sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(8125), '
        'sin_addr=inet_addr("198.51.100.44")}, msg_namelen=16, '
        'msg_iov=[{iov_base="metric=0'
    )
    assert parse_send_line(truncated, None) is None
    print("✓ Truncated send line dropped rather than given a fabricated result")

    # A payload containing '= 0' well before a real return must not confuse it.
    embedded = (
        '12345 1.0 sendto(4, "x = 0 and y = 1", 15, 0, {sa_family=AF_INET, '
        'sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 EPERM'
    )
    parsed = parse_send_line(embedded, None)
    assert parsed is not None
    _, events = parsed
    assert events[0]["result"] == "error"
    assert events[0]["errno"] == "EPERM"
    print("✓ Real return value preferred over '= N' inside the payload")


def test_parse_to_jsonl_captures_unconnected_udp():
    """End-to-end: a dnspython-shaped trace reports its nameserver destination.

    dnspython resolves with sendto() on an unconnected socket and never calls
    connect(), so before send* parsing this whole trace produced zero events.
    """
    strace_content = """12345 1707150823.500 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 3
12345 1707150823.510 sendto(3, "\\253\\17\\1\\0", 29, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.31.158.1")}, 16) = 29
12345 1707150823.530 recvfrom(3, "\\253\\17\\201\\200", 65535, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.31.158.1")}, [16]) = 129
12345 1707150823.600 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 4
12345 1707150823.610 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
12345 1707150823.700 sendmsg(5, {msg_name={sa_family=AF_INET, sin_port=htons(8125), sin_addr=inet_addr("198.51.100.44")}, msg_namelen=16, msg_iov=[{iov_base="m", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 1
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"
        strace_file.write_text(strace_content)

        count = parse_to_jsonl(strace_file, jsonl_file)
        assert count == 3, f"Expected 3 events, got {count}"

        events = [json.loads(line) for line in jsonl_file.read_text().strip().split("\n")]
        destinations = {(e["dst_ip"], e["dst_port"]) for e in events}
        assert ("10.31.158.1", 53) in destinations, "nameserver destination was dropped"
        assert ("93.184.216.34", 443) in destinations
        assert ("198.51.100.44", 8125) in destinations

        # recvfrom carries a sockaddr too, but it is inbound: it must not be
        # reported as an egress event beyond the sendto to the same peer.
        assert sum(1 for e in events if e["dst_ip"] == "10.31.158.1") == 1
        assert events[0]["proto"] == "udp"
        assert events[0]["event"] == "sendto"

    print("✓ Unconnected UDP destinations captured end to end")


def parse_events(strace_content: str) -> tuple:
    """Parse a trace body and return (events, stats)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        strace_file = tmp_path / "strace.out"
        jsonl_file = tmp_path / "egress.jsonl"
        strace_file.write_text(strace_content)

        stats: dict = {}
        parse_to_jsonl(strace_file, jsonl_file, stats)
        body = jsonl_file.read_text().strip()
        events = [json.loads(line) for line in body.split("\n")] if body else []
        return events, stats


def test_udp_connect_without_traffic_is_not_reported_as_egress():
    """A real getaddrinfo() trace: the sorting probes are not destinations.

    Captured from `socket.gethostbyname("example.com")` in the tracing image.
    glibc resolves the name, then connect()s a UDP socket to each answer address
    and calls getsockname() to see which source address the kernel would pick.
    connect() on a UDP socket transmits nothing, so example.com's two addresses
    were never contacted -- yet the report named them, and 2 of its 3 events and
    2 of its 3 unique destinations were addresses the app never sent a byte to.

    Note fd 3 is reused throughout: two AF_UNIX sockets, the resolver's UDP
    socket, a netlink socket, then the probes. Only the resolver's connect()
    survives, and it survives because of the sendto() that follows it.
    """
    events, stats = parse_events(
        '11 1787224802.263919 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3\n'
        '11 1787224802.264111 connect(3, {sa_family=AF_UNIX, '
        'sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)\n'
        '11 1787224802.264465 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, '
        'IPPROTO_IP) = 3\n'
        '11 1787224802.264573 connect(3, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("192.168.65.7")}, 16) = 0\n'
        '11 1787224802.264662 sendto(3, "l\\4\\1\\0", 29, MSG_NOSIGNAL, NULL, 0) = 29\n'
        '11 1787224802.285025 recvfrom(3, "l\\4\\201\\200", 1024, 0, '
        '{sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("192.168.65.7")}, [28 => 16]) = 83\n'
        '11 1787224802.285224 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3\n'
        '11 1787224802.285814 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3\n'
        '11 1787224802.285880 connect(3, {sa_family=AF_INET, sin_port=htons(0), '
        'sin_addr=inet_addr("104.20.23.154")}, 16) = 0\n'
        '11 1787224802.285969 getsockname(3, {sa_family=AF_INET, sin_port=htons(37034), '
        'sin_addr=inet_addr("172.17.0.2")}, [28 => 16]) = 0\n'
        '11 1787224802.286080 connect(3, {sa_family=AF_UNSPEC, sa_data="\\0\\0"}, 16) = 0\n'
        '11 1787224802.286135 connect(3, {sa_family=AF_INET, sin_port=htons(0), '
        'sin_addr=inet_addr("172.66.147.243")}, 16) = 0\n'
        '11 1787224802.286193 getsockname(3, {sa_family=AF_INET, sin_port=htons(39758), '
        'sin_addr=inet_addr("172.17.0.2")}, [28 => 16]) = 0\n'
    )

    assert [(e["dst_ip"], e["dst_port"]) for e in events] == [("192.168.65.7", 53)]
    assert stats["udp_probes_skipped"] == 2


def test_a_probe_and_real_traffic_on_the_same_fd_are_told_apart():
    """fd reuse must not let the probe's silence cost the real socket its event.

    Same fd number, two sockets: the first is connect()ed and never used, the
    second sends. Keyed by (pid, fd) alone this is one socket with traffic, and
    the probe would be reported; keyed by the connect count on that fd, only the
    second survives.
    """
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(0), '
        'sin_addr=inet_addr("203.0.113.9")}, 16) = 0\n'
        '7 1.2 getsockname(4, {sa_family=AF_INET, sin_port=htons(1234)}, [16]) = 0\n'
        '7 2.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 2.1 connect(4, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = 0\n'
        '7 2.2 sendto(4, "q", 1, MSG_NOSIGNAL, NULL, 0) = 1\n'
    )

    assert [(e["dst_ip"], e["dst_port"]) for e in events] == [("10.0.0.53", 53)]
    assert stats["udp_probes_skipped"] == 1


def test_traffic_before_a_probe_does_not_rescue_it():
    """The real socket sends first, then the fd is reused for a probe.

    The reverse order of the test above, which is the ordering a naive "did this
    fd ever carry traffic" check gets wrong in the dangerous direction: it would
    report the probe's address as a destination.
    """
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = 0\n'
        '7 1.2 sendto(4, "q", 1, MSG_NOSIGNAL, NULL, 0) = 1\n'
        '7 2.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 2.1 connect(4, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("203.0.113.9")}, 16) = 0\n'
        '7 2.2 getsockname(4, {sa_family=AF_INET, sin_port=htons(1234)}, [16]) = 0\n'
    )

    assert [(e["dst_ip"], e["dst_port"]) for e in events] == [("10.0.0.53", 53)]
    # Port 443, not 0: the filter is behavioural, and a probe to a real port is
    # still a probe.
    assert stats["udp_probes_skipped"] == 1


def test_a_connect_answered_only_by_a_receive_is_kept():
    """Errs towards reporting: a reply implies a request, even an untraced one."""
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(123), '
        'sin_addr=inet_addr("10.0.0.123")}, 16) = 0\n'
        '7 1.2 recvfrom(4, "t", 48, 0, NULL, NULL) = 48\n'
    )

    assert [(e["dst_ip"], e["dst_port"]) for e in events] == [("10.0.0.123", 123)]
    assert stats["udp_probes_skipped"] == 0


def test_a_split_udp_connect_is_filtered_on_the_epoch_of_its_entry_line():
    """The unfinished half carries the fd; the resumed half is where it is judged."""
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(0), '
        'sin_addr=inet_addr("203.0.113.9")}, 16 <unfinished ...>\n'
        '7 1.2 <... connect resumed>) = 0\n'
    )

    assert events == []
    assert stats["udp_probes_skipped"] == 1


def test_a_silent_tcp_connect_is_still_egress():
    """Only UDP is filtered: a TCP connect() puts a SYN on the wire by itself."""
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = 0\n'
    )

    assert [(e["dst_ip"], e["proto"]) for e in events] == [("93.184.216.34", "tcp")]
    assert stats["udp_probes_skipped"] == 0


def test_a_silent_connect_on_an_unlabelled_socket_is_still_egress():
    """No socket() line means no protocol, and a guess is not worth an omission."""
    events, stats = parse_events(
        '7 1.1 connect(9, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = 0\n'
    )

    assert [(e["dst_ip"], e["proto"]) for e in events] == [("10.0.0.53", "unknown")]
    assert stats["udp_probes_skipped"] == 0


def test_a_payload_that_looks_like_a_connect_cannot_hide_a_destination():
    """The traced process must not be able to delete its own events.

    strace prints captured buffers verbatim, so a process can send a datagram
    whose payload reads like a connect() line. If the pre-pass stopped at that
    match instead of also recording the send, the socket would look silent and
    its real destination would be filtered out -- a self-service exemption from
    the ip/CIDR gate.
    """
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = 0\n'
        '7 1.2 sendto(4, "1 1.0 connect(1, junk", 21, MSG_NOSIGNAL, NULL, 0) = 21\n'
    )

    assert [(e["dst_ip"], e["dst_port"]) for e in events] == [("10.0.0.53", 53)]
    assert stats["udp_probes_skipped"] == 0


def test_a_refused_udp_connect_is_still_reported():
    """Blocked egress is egress that was attempted.

    Pointing a datagram socket at a peer is a local operation, so the sorting
    probes always succeed; an error means something denied an attempt the app
    made, and hiding that would understate the report in the one direction that
    matters.
    """
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4\n'
        '7 1.1 connect(4, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = -1 EACCES (Permission denied)\n'
    )

    assert [(e["dst_ip"], e["result"], e["errno"]) for e in events] == [
        ("10.0.0.53", "error", "EACCES")
    ]
    assert stats["udp_probes_skipped"] == 0


def test_unconnected_udp_sends_are_untouched_by_the_probe_filter():
    """dnspython's shape: sendto() names its own destination and never connects."""
    events, stats = parse_events(
        '7 1.0 socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP) = 4\n'
        '7 1.1 sendto(4, "q", 29, 0, {sa_family=AF_INET, sin_port=htons(53), '
        'sin_addr=inet_addr("10.0.0.53")}, 16) = 29\n'
    )

    assert [(e["dst_ip"], e["event"]) for e in events] == [("10.0.0.53", "sendto")]
    assert stats["udp_probes_skipped"] == 0


if __name__ == "__main__":
    print("Testing strace parser...")
    test_parse_strace_line()
    test_parse_socket_line()
    test_parse_split_connect_line()
    test_parse_to_jsonl()
    test_ipv6_connects_counted_not_captured()
    test_parse_sendto_line()
    test_parse_sendmsg_line()
    test_parse_sendmmsg_line()
    test_parse_failed_send_line()
    test_parse_split_send_line()
    test_truncated_send_line_is_not_given_a_fabricated_result()
    test_parse_to_jsonl_captures_unconnected_udp()
    test_udp_connect_without_traffic_is_not_reported_as_egress()
    test_a_probe_and_real_traffic_on_the_same_fd_are_told_apart()
    test_traffic_before_a_probe_does_not_rescue_it()
    test_a_connect_answered_only_by_a_receive_is_kept()
    test_a_split_udp_connect_is_filtered_on_the_epoch_of_its_entry_line()
    test_a_silent_tcp_connect_is_still_egress()
    test_a_silent_connect_on_an_unlabelled_socket_is_still_egress()
    test_a_payload_that_looks_like_a_connect_cannot_hide_a_destination()
    test_a_refused_udp_connect_is_still_reported()
    test_unconnected_udp_sends_are_untouched_by_the_probe_filter()
    print("\nAll tests passed! ✓")
