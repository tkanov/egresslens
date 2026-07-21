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
    assert policy.allows("1.2.3.4", 443, "api.github.com")
    assert policy.allows("140.82.112.5", 443, None)  # inside the CIDR
    assert not policy.allows("140.82.128.1", 443, None)  # outside the CIDR


def test_object_rule_with_port():
    policy = load_policy({"allow": [{"ip": "10.0.0.0/8", "port": 443}]})
    assert policy.allows("10.1.2.3", 443, None)
    assert not policy.allows("10.1.2.3", 8080, None)  # wrong port


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


def test_unexpected_sorted_by_count_desc():
    events = [event("2.2.2.2")] + [event("3.3.3.3")] * 3
    policy = load_policy({"allow": ["example.com"]})
    verdict = evaluate_policy(policy, events, {})
    assert [d["dst_ip"] for d in verdict["unexpected"]] == ["3.3.3.3", "2.2.2.2"]


def main():
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
