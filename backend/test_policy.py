#!/usr/bin/env python3
"""Unit tests for the egress allowlist policy (parsing, matching, verdict)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest

from app.enrichment import DomainCandidate
from app.policy import (
    PolicyError,
    domain_matches,
    evaluate_policy,
    load_policy,
    resolve_destinations,
)
from app.schemas import EventSchema


def event(ip: str, port: int = 443, proto: str = "tcp") -> EventSchema:
    return EventSchema(
        ts=1.0,
        pid=1,
        event="connect",
        family="inet",
        proto=proto,
        dst_ip=ip,
        dst_port=port,
        result="ok",
    )


def candidates(mapping: dict) -> dict:
    """Build a domain_candidates dict {ip: [DomainCandidate(passive_dns)]}."""
    return {
        ip: [DomainCandidate(domain=domain, source="passive_dns", count=1)]
        for ip, domain in mapping.items()
    }


# --- domain_matches: wildcard boundaries are a security boundary ---------------

def test_wildcard_matches_subdomains():
    assert domain_matches("*.example.com", "api.example.com")
    assert domain_matches("*.example.com", "a.b.example.com")


def test_wildcard_does_not_match_apex():
    # Convention: a leading-wildcard rule covers subdomains only, not the apex.
    assert not domain_matches("*.example.com", "example.com")


def test_wildcard_does_not_match_lookalikes():
    # These are the classic endswith() bypasses a naive matcher would allow.
    assert not domain_matches("*.example.com", "notexample.com")
    assert not domain_matches("*.example.com", "fooexample.com")
    assert not domain_matches("*.example.com", "example.com.evil.com")


def test_exact_match_is_not_a_suffix_match():
    assert domain_matches("example.com", "example.com")
    assert not domain_matches("example.com", "api.example.com")
    assert not domain_matches("example.com", "evilexample.com")


def test_matching_is_case_insensitive():
    assert domain_matches("*.Example.COM", "API.example.com")


# --- load_policy: reject malformed documents so typos fail loudly --------------

def test_shorthand_domain_and_ip_tokens():
    policy = load_policy({"allow": ["*.github.com", "pypi.org", "140.82.112.0/20"]})
    assert len(policy.rules) == 3
    assert policy.allows("1.2.3.4", 443, ["api.github.com"])
    assert policy.allows("140.82.112.5", 443, [])  # inside the CIDR, no domain
    assert not policy.allows("140.82.128.1", 443, [])  # outside the CIDR


def test_object_rule_with_port():
    policy = load_policy({"allow": [{"ip": "10.0.0.0/8", "port": 443}]})
    assert policy.allows("10.1.2.3", 443, [])
    assert not policy.allows("10.1.2.3", 8080, [])  # wrong port


def test_object_rule_with_domain_and_port_is_anded():
    policy = load_policy({"allow": [{"domain": "example.com", "port": 443}]})
    assert policy.allows("1.2.3.4", 443, ["example.com"])
    assert not policy.allows("1.2.3.4", 8080, ["example.com"])  # right domain, wrong port


def test_domain_path_fails_closed_when_a_candidate_is_unlisted():
    # A shared IP that serves both an allowed and a disallowed name must NOT pass
    # just because the allowed one is primary -- otherwise the verdict fails open.
    policy = load_policy({"allow": ["*.allowed.com"]})
    assert policy.allows("1.2.3.4", 443, ["cdn.allowed.com"])
    assert not policy.allows("1.2.3.4", 443, ["cdn.allowed.com", "analytics.tracker.com"])


def test_missing_allow_rejected():
    with pytest.raises(PolicyError):
        load_policy({"rules": []})


def test_non_dict_rejected():
    with pytest.raises(PolicyError):
        load_policy(["*.github.com"])


def test_empty_allow_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": []})


def test_rule_without_domain_or_ip_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [{"port": 443}]})


def test_unknown_key_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [{"domian": "example.com"}]})


def test_invalid_wildcard_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": ["*foo.com"]})
    with pytest.raises(PolicyError):
        load_policy({"allow": ["a.*.com"]})


def test_malformed_domain_labels_rejected():
    # Junk that would become a silently never-matching rule must be rejected.
    for bad in ["-", "---", "a..b", "-a.com", "a-.com"]:
        with pytest.raises(PolicyError):
            load_policy({"allow": [bad]})


def test_too_many_rules_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [f"host{i}.example.com" for i in range(1001)]})


def test_bad_ip_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [{"ip": "not-an-ip"}]})


def test_port_out_of_range_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [{"ip": "10.0.0.0/8", "port": 70000}]})


def test_bool_port_rejected():
    with pytest.raises(PolicyError):
        load_policy({"allow": [{"ip": "10.0.0.0/8", "port": True}]})


# --- evaluate_policy: the verdict over ALL destinations ------------------------

def test_verdict_pass_when_all_expected():
    events = [event("140.82.112.3"), event("93.184.216.34")]
    doms = candidates({"93.184.216.34": "example.com"})
    policy = load_policy({"allow": ["example.com", "140.82.112.0/20"]})
    verdict = evaluate_policy(policy, events, doms)
    assert verdict["verdict"] == "pass"
    assert verdict["expected_count"] == 2
    assert verdict["unexpected_count"] == 0


def test_verdict_fail_lists_unexpected():
    events = [event("93.184.216.34"), event("8.8.8.8", 53, "udp")]
    doms = candidates({"93.184.216.34": "example.com"})
    policy = load_policy({"allow": ["example.com"]})
    verdict = evaluate_policy(policy, events, doms)
    assert verdict["verdict"] == "fail"
    assert verdict["unexpected_count"] == 1
    unexpected = verdict["unexpected"][0]
    assert unexpected["dst_ip"] == "8.8.8.8"
    assert unexpected["domain"] is None


def test_unresolved_ip_matches_ip_rule_only():
    # A destination we could not name is expected only if an IP/CIDR rule covers
    # it; a domain rule can never vouch for an unnamed IP.
    events = [event("203.0.113.7")]
    policy_domain_only = load_policy({"allow": ["example.com"]})
    assert evaluate_policy(policy_domain_only, events, {})["verdict"] == "fail"

    policy_with_ip = load_policy({"allow": ["203.0.113.0/24"]})
    assert evaluate_policy(policy_with_ip, events, {})["verdict"] == "pass"


def test_wildcard_rule_over_destinations():
    events = [event("1.1.1.1"), event("2.2.2.2")]
    doms = candidates({"1.1.1.1": "api.github.com", "2.2.2.2": "evil.example.com"})
    policy = load_policy({"allow": ["*.github.com"]})
    verdict = evaluate_policy(policy, events, doms)
    assert verdict["verdict"] == "fail"
    assert verdict["unexpected"][0]["domain"] == "evil.example.com"


def test_verdict_covers_destinations_beyond_top_50():
    # The verdict must judge EVERY destination, not just the top 50 shown in the
    # summary table. The one unexpected destination here has the lowest count, so
    # a naive top-50-by-count cap would drop it and silently pass a real egress.
    events = []
    for i in range(1, 55):  # 54 allowed destinations, count 2 each
        events += [event(f"10.0.0.{i}")] * 2
    events.append(event("203.0.113.9"))  # 1 unexpected destination, count 1 (last)
    policy = load_policy({"allow": ["10.0.0.0/8"]})
    verdict = evaluate_policy(policy, events, {})
    assert verdict["verdict"] == "fail"
    assert verdict["unexpected_count"] == 1
    assert verdict["unexpected"][0]["dst_ip"] == "203.0.113.9"


def test_unexpected_sorted_by_count_desc():
    events = [event("2.2.2.2")] + [event("3.3.3.3")] * 3
    policy = load_policy({"allow": ["example.com"]})
    verdict = evaluate_policy(policy, events, {})
    assert [d["dst_ip"] for d in verdict["unexpected"]] == ["3.3.3.3", "2.2.2.2"]


def test_evaluate_fails_closed_on_shared_ip_masking():
    # End-to-end through evaluate_policy: an IP whose primary domain is allowed
    # but which also served a disallowed name must be reported unexpected.
    events = [event("1.2.3.4")] * 4
    doms = {
        "1.2.3.4": [
            DomainCandidate(domain="cdn.allowed.com", source="passive_dns", count=3),
            DomainCandidate(domain="analytics.tracker.com", source="passive_dns", count=1),
        ]
    }
    policy = load_policy({"allow": ["*.allowed.com"]})
    verdict = evaluate_policy(policy, events, doms)
    assert verdict["verdict"] == "fail"
    assert verdict["unexpected_count"] == 1
    assert verdict["unexpected"][0]["domain"] == "cdn.allowed.com"  # primary, for display


def test_unexpected_list_capped_but_count_stays_exact():
    events = [event(f"203.0.113.{i}") for i in range(60)]  # 60 distinct, none allowed
    policy = load_policy({"allow": ["10.0.0.0/8"]})
    verdict = evaluate_policy(policy, events, {})
    assert verdict["unexpected_count"] == 60
    assert len(verdict["unexpected"]) == 50


def test_has_domain_rules_flag():
    events = [event("10.0.0.1")]
    assert evaluate_policy(load_policy({"allow": ["*.x.com"]}), events, {})["has_domain_rules"]
    assert not evaluate_policy(load_policy({"allow": ["10.0.0.0/8"]}), events, {})["has_domain_rules"]


def test_md_escape_neutralizes_table_injection():
    from app.main import _md_escape
    assert _md_escape("evil.com | fake") == "evil.com \\| fake"
    assert "\n" not in _md_escape("line1\nline2")
    assert _md_escape("`code`") == "\\`code\\`"


class CountingEvents(list):
    """A list that records how many times it has been iterated."""

    def __init__(self, items):
        super().__init__(items)
        self.scans = 0

    def __iter__(self):
        self.scans += 1
        return super().__iter__()


def attributed_event(ip: str, domain: str, source: str, port: int = 443) -> EventSchema:
    """An event that already carries a domain attribution, as an upload may."""
    return EventSchema(
        ts=1.0,
        pid=1,
        event="connect",
        family="inet",
        proto="tcp",
        dst_ip=ip,
        dst_port=port,
        result="ok",
        domain=domain,
        domain_source=source,
    )


def test_resolve_destinations_scans_events_a_fixed_number_of_times():
    """The event scan count must not grow with the number of destinations.

    resolve_destinations used to rescan every event once per destination to find
    event-carried domain attributions, i.e. O(destinations * events). Because the
    verdict covers every destination rather than a displayed top-N, that
    dominated the whole upload: 588s on a report at the 50 MB cap, on a
    synchronous endpoint holding a worker thread. Counting iterations rather than
    timing keeps this guard deterministic on shared CI.
    """
    few = CountingEvents([event(f"10.0.0.{i}") for i in range(5)])
    many = CountingEvents([event(f"10.1.{i // 256}.{i % 256}") for i in range(300)])

    assert len(resolve_destinations(few, {})) == 5
    assert len(resolve_destinations(many, {})) == 300

    assert few.scans == many.scans, (
        "event scans grew with destination count: "
        f"{few.scans} for 5 destinations, {many.scans} for 300"
    )
    assert many.scans <= 4, f"expected a small constant scan count, got {many.scans}"


def test_enrichment_attribution_takes_precedence_over_event_attribution():
    events = [attributed_event("1.1.1.1", "from-event.example", "reverse_dns")]
    resolved = resolve_destinations(events, candidates({"1.1.1.1": "from-enrichment.example"}))
    assert resolved[0]["domain"] == "from-enrichment.example"
    assert resolved[0]["domains"] == ["from-enrichment.example"]


def test_empty_enrichment_entry_falls_through_to_event_attribution():
    """An IP present in domain_candidates with an empty list must still fall back."""
    events = [attributed_event("1.1.1.1", "from-event.example", "passive_dns")]
    resolved = resolve_destinations(events, {"1.1.1.1": []})
    assert resolved[0]["domain"] == "from-event.example"
    assert resolved[0]["domains"] == ["from-event.example"]


def test_verdict_uses_event_carried_domains_without_enrichment():
    """A pre-enriched upload is judged on its own attribution, with no strace."""
    events = [
        attributed_event("1.1.1.1", "allowed.example", "passive_dns"),
        attributed_event("2.2.2.2", "blocked.example", "passive_dns"),
    ]
    verdict = evaluate_policy(load_policy({"allow": ["allowed.example"]}), events, {})
    assert verdict["verdict"] == "fail"
    assert verdict["unexpected_count"] == 1
    assert verdict["unexpected"][0]["domain"] == "blocked.example"


def main():
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
