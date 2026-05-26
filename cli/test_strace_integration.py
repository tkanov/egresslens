#!/usr/bin/env python3
"""Integration harness for parsing real strace network output."""

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from egresslens.strace_parser import parse_to_jsonl


TRACE_PROGRAM = r"""
import socket
import threading


def serve_once(server_socket):
    conn, _ = server_socket.accept()
    conn.close()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 0))
server.listen(1)
server_port = server.getsockname()[1]

thread = threading.Thread(target=serve_once, args=(server,))
thread.start()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", server_port))
client.close()

thread.join(timeout=5)
server.close()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(("127.0.0.1", 9))
udp.close()
"""


def load_jsonl(path: Path) -> list[dict]:
    """Load JSONL events from a file."""
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def failure_context(strace_path: Path, events: list[dict]) -> str:
    """Build compact debugging context for integration test failures."""
    strace_excerpt = "\n".join(
        line
        for line in strace_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if "socket(" in line or "connect(" in line
    )
    return (
        f"events:\n{json.dumps(events, indent=2)}\n\n"
        f"socket/connect strace lines:\n{strace_excerpt}"
    )


def test_real_strace_protocol_detection() -> None:
    """Run real strace and verify socket-derived TCP/UDP protocol labels."""
    if not shutil.which("strace"):
        print("⊘ Skipping real strace integration test (strace not found)")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        program_path = tmp_path / "trace_target.py"
        strace_path = tmp_path / "egress.strace"
        jsonl_path = tmp_path / "egress.jsonl"

        program_path.write_text(textwrap.dedent(TRACE_PROGRAM), encoding="utf-8")

        result = subprocess.run(
            [
                "strace",
                "-f",
                "-ttt",
                "-e",
                "trace=network",
                "-o",
                str(strace_path),
                sys.executable,
                str(program_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, (
            f"trace target failed with exit code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

        parsed_count = parse_to_jsonl(strace_path, jsonl_path)
        events = load_jsonl(jsonl_path)
        context = failure_context(strace_path, events)

        assert parsed_count == len(events)
        assert parsed_count >= 2, (
            f"Expected at least TCP and UDP events, got {parsed_count}\n{context}"
        )

        loopback_events = [event for event in events if event["dst_ip"] == "127.0.0.1"]
        assert any(
            event["proto"] == "tcp" and event["result"] == "ok" for event in loopback_events
        ), context
        assert any(
            event["proto"] == "udp" and event["dst_port"] == 9 for event in loopback_events
        ), context

        print("✓ Real strace output produced TCP and UDP protocol labels")


if __name__ == "__main__":
    print("Testing real strace parser integration...")
    test_real_strace_protocol_detection()
    print("\nIntegration test passed! ✓")
