#!/usr/bin/env python3
"""Unit tests for compute_aggregates (protocol selection and basic counts)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.main import _md_escape, compute_aggregates
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


def test_top_destinations_use_event_domain_attribution():
    """compute_aggregates shares the one-pass event-attribution helper.

    Passive DNS outranks reverse DNS for the primary domain, and every observed
    name is listed with its count.
    """
    def attributed(ip: str, domain: str, source: str) -> EventSchema:
        return EventSchema(
            ts=1.0,
            pid=1,
            event="connect",
            family="inet",
            proto="tcp",
            dst_ip=ip,
            dst_port=443,
            result="ok",
            domain=domain,
            domain_source=source,
        )

    summary = compute_aggregates(
        [
            attributed("1.1.1.1", "a.example", "passive_dns"),
            attributed("1.1.1.1", "a.example", "passive_dns"),
            attributed("1.1.1.1", "b.example", "reverse_dns"),
        ],
        {},
    )

    dest = summary["top_destinations"][0]
    assert dest["domain"] == "a.example"
    assert dest["domain_source"] == "passive_dns"
    assert [d["domain"] for d in dest["domains"]] == ["a.example", "b.example"]
    assert [d["count"] for d in dest["domains"]] == [2, 1]
    print("✓ top destinations use event-carried domain attribution")


def test_md_escape_neutralizes_table_injection():
    # Lives here rather than beside the policy tests, which moved to cli/, because
    # _md_escape belongs to the backend's markdown export, not to the engine.
    assert _md_escape("evil.com | fake") == "evil.com \\| fake"
    assert "\n" not in _md_escape("line1\nline2")
    assert _md_escape("`code`") == "\\`code\\`"


def main():
    test_modal_protocol_per_destination()
    test_protocol_tie_breaks_on_first_seen()
    test_empty_events()
    test_top_destinations_use_event_domain_attribution()
    test_md_escape_neutralizes_table_injection()
    print("all aggregate tests passed")


if __name__ == "__main__":
    main()
