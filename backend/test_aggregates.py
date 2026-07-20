#!/usr/bin/env python3
"""Unit tests for compute_aggregates (protocol selection and basic counts)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.main import compute_aggregates
from app.schemas import EventSchema


def event(ip: str, port: int = 443, proto: str = "tcp", result: str = "ok") -> EventSchema:
    return EventSchema(
        ts=1.0,
        pid=1,
        event="connect",
        family="inet",
        proto=proto,
        dst_ip=ip,
        dst_port=port,
        result=result,
    )


def test_modal_protocol_per_destination():
    events = [
        event("1.1.1.1", 53, "udp"),
        event("1.1.1.1", 53, "udp"),
        event("1.1.1.1", 53, "tcp"),  # udp wins 2-1
        event("2.2.2.2", 443, "tcp"),
    ]
    summary = compute_aggregates(events)
    by_dest = {
        (d["dst_ip"], d["dst_port"]): d["proto"] for d in summary["top_destinations"]
    }
    assert by_dest[("1.1.1.1", 53)] == "udp", by_dest
    assert by_dest[("2.2.2.2", 443)] == "tcp", by_dest
    assert summary["total_events"] == 4
    assert summary["unique_destinations"] == 2
    print("✓ modal protocol chosen per destination")


def test_protocol_tie_breaks_on_first_seen():
    # One tcp, one udp for the same destination: the first-seen protocol wins,
    # matching Counter.most_common insertion-order tie-breaking.
    events = [event("9.9.9.9", 443, "tcp"), event("9.9.9.9", 443, "udp")]
    summary = compute_aggregates(events)
    assert summary["top_destinations"][0]["proto"] == "tcp"
    print("✓ protocol ties break on first-seen order")


def test_empty_events():
    summary = compute_aggregates([])
    assert summary["total_events"] == 0
    assert summary["top_destinations"] == []
    print("✓ empty events handled")


def main():
    test_modal_protocol_per_destination()
    test_protocol_tie_breaks_on_first_seen()
    test_empty_events()
    print("all aggregate tests passed")


if __name__ == "__main__":
    main()
