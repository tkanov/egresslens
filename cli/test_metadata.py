#!/usr/bin/env python3
"""Simple test script for metadata generator."""

import json
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from egresslens.metadata import (
    count_events_from_jsonl,
    generate_metadata,
    write_metadata,
)


def test_generate_metadata():
    """Test metadata generation."""
    run_id = str(uuid.uuid4())
    start_time = datetime(2024, 1, 1, 12, 0, 0)
    end_time = datetime(2024, 1, 1, 12, 1, 0)

    metadata = generate_metadata(
        run_id=run_id,
        start_time=start_time,
        end_time=end_time,
        exit_code=0,
        mode="docker",
        image="ubuntu:24.04",
        command=["curl", "https://example.com"],
        cwd=Path("/tmp/test"),
        total_events=5,
        unique_dst_ips=3,
        unique_dst_ip_ports=4,
    )

    assert metadata["run_id"] == run_id
    assert metadata["exit_code"] == 0
    assert metadata["mode"] == "docker"
    assert metadata["image"] == "ubuntu:24.04"
    assert metadata["command"] == ["curl", "https://example.com"]
    assert metadata["counts"]["total_events"] == 5
    assert metadata["counts"]["unique_dst_ips"] == 3
    assert metadata["counts"]["unique_dst_ip_ports"] == 4
    print("✓ Successfully generated metadata")


def test_write_metadata():
    """Test writing metadata to file."""
    metadata = generate_metadata(
        run_id=str(uuid.uuid4()),
        start_time=datetime.now(),
        end_time=datetime.now(),
        exit_code=0,
        mode="docker",
        image="ubuntu:24.04",
        command=["test"],
        cwd=Path("/tmp"),
        total_events=1,
        unique_dst_ips=1,
        unique_dst_ip_ports=1,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "run.json"
        write_metadata(metadata, output_path)

        assert output_path.exists()
        loaded = json.loads(output_path.read_text())
        assert loaded["run_id"] == metadata["run_id"]
        print("✓ Successfully wrote metadata to file")


def test_count_events_from_jsonl():
    """Test counting events from JSONL."""
    jsonl_content = """{"ts": 1.0, "pid": 1, "dst_ip": "1.2.3.4", "dst_port": 443}
{"ts": 2.0, "pid": 1, "dst_ip": "1.2.3.4", "dst_port": 443}
{"ts": 3.0, "pid": 2, "dst_ip": "5.6.7.8", "dst_port": 80}
{"ts": 4.0, "pid": 3, "dst_ip": "1.2.3.4", "dst_port": 53}
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        jsonl_path = Path(tmpdir) / "egress.jsonl"
        jsonl_path.write_text(jsonl_content)

        total, unique_ips, unique_ip_ports = count_events_from_jsonl(jsonl_path)

        assert total == 4
        assert unique_ips == 2  # 1.2.3.4 and 5.6.7.8
        assert unique_ip_ports == 3  # 1.2.3.4:443, 5.6.7.8:80, 1.2.3.4:53
        print("✓ Successfully counted events from JSONL")


if __name__ == "__main__":
    print("Testing metadata generator...")
    test_generate_metadata()
    test_write_metadata()
    test_count_events_from_jsonl()
    print("\nAll tests passed! ✓")
