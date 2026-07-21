"""Egress policy: judge a report's destinations against a declared allowlist.

A policy is an optional, per-report allowlist uploaded alongside the report. It
declares the destinations an app is *expected* to reach; anything observed that
does not match a rule is reported as unexpected. This turns a descriptive report
("here is what happened") into a verdict ("here is what should not have").

The verdict is computed at upload time in the backend because that is the only
place domains exist: the CLI captures IP/port connect events, and domain
attribution (passive + reverse DNS) happens during enrichment.

Policy file format (JSON)::

    {
      "allow": [
        "*.github.com",                       // wildcard domain (subdomains only)
        "pypi.org",                           // exact domain
        "140.82.112.0/20",                    // IP or CIDR
        {"domain": "files.pythonhosted.org"}, // explicit object form
        {"ip": "151.101.0.0/16", "port": 443} // constrain the port too
      ]
    }

A destination is *expected* if it matches at least one allow rule. A rule matches
only when every field it declares matches, so a bare ``ip`` rule allows any port
and a bare ``domain`` rule allows any address that resolves to it.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional, Union

from app.enrichment import DomainCandidate, choose_primary_domain
from app.schemas import EventSchema

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Domain labels only ever contain these characters, plus a single leading "*."
# wildcard that we handle separately. Rejecting anything else keeps a typo from
# silently becoming a rule that never (or always) matches.
_DOMAIN_BODY_RE = re.compile(r"[a-z0-9.-]+")


class PolicyError(ValueError):
    """Raised when an uploaded policy document is malformed."""


@dataclass
class AllowRule:
    """One allowlist entry. A destination matches only if every set field does."""

    domain: Optional[str] = None
    network: Optional[IPNetwork] = None
    port: Optional[int] = None
    source: str = ""

    def matches(self, ip: str, port: int, domain: Optional[str]) -> bool:
        if self.port is not None and port != self.port:
            return False
        if self.network is not None:
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                return False
            if address not in self.network:
                return False
        if self.domain is not None:
            if domain is None or not domain_matches(self.domain, domain):
                return False
        return True


@dataclass
class Policy:
    """A parsed allowlist."""

    rules: List[AllowRule] = field(default_factory=list)

    def allows(self, ip: str, port: int, domain: Optional[str]) -> bool:
        return any(rule.matches(ip, port, domain) for rule in self.rules)


def domain_matches(pattern: str, domain: str) -> bool:
    """Match a destination domain against an allowlist pattern.

    ``*.example.com`` matches ``api.example.com`` and ``a.b.example.com`` but not
    the apex ``example.com`` nor look-alikes such as ``notexample.com`` or
    ``example.com.evil.com`` -- the leading-dot boundary is what makes this safe
    to use in a security verdict. Any other pattern is an exact, case-insensitive
    match.
    """
    pattern = pattern.lower()
    domain = domain.lower()
    if pattern.startswith("*."):
        return domain.endswith(pattern[1:])
    return domain == pattern


def load_policy(data: object) -> Policy:
    """Parse and validate a policy document, raising PolicyError on any problem."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    if "allow" not in data:
        raise PolicyError("policy must contain an 'allow' list")
    allow = data["allow"]
    if not isinstance(allow, list):
        raise PolicyError("policy 'allow' must be a list")
    if not allow:
        raise PolicyError("policy 'allow' must contain at least one rule")

    rules = [_parse_rule(entry, index) for index, entry in enumerate(allow)]
    return Policy(rules=rules)


def _parse_rule(entry: object, index: int) -> AllowRule:
    where = f"allow[{index}]"
    if isinstance(entry, str):
        return _rule_from_token(entry, where)
    if isinstance(entry, dict):
        return _rule_from_object(entry, where)
    raise PolicyError(f"{where} must be a string or an object")


def _rule_from_token(token: str, where: str) -> AllowRule:
    """Interpret a shorthand string as an IP/CIDR rule, else a domain rule."""
    stripped = token.strip()
    if not stripped:
        raise PolicyError(f"{where} is empty")
    network = _try_network(stripped)
    if network is not None:
        return AllowRule(network=network, source=stripped)
    return AllowRule(domain=_validate_domain(stripped, where), source=stripped)


def _rule_from_object(obj: dict, where: str) -> AllowRule:
    unknown = set(obj) - {"domain", "ip", "port"}
    if unknown:
        raise PolicyError(f"{where} has unknown key(s): {sorted(unknown)}")

    domain_val = obj.get("domain")
    ip_val = obj.get("ip")
    port_val = obj.get("port")

    if domain_val is None and ip_val is None:
        raise PolicyError(f"{where} must set 'domain' or 'ip'")

    domain = None
    if domain_val is not None:
        if not isinstance(domain_val, str):
            raise PolicyError(f"{where} 'domain' must be a string")
        domain = _validate_domain(domain_val, where)

    network = None
    if ip_val is not None:
        if not isinstance(ip_val, str):
            raise PolicyError(f"{where} 'ip' must be a string")
        network = _try_network(ip_val)
        if network is None:
            raise PolicyError(f"{where} 'ip' is not a valid IP address or CIDR: {ip_val!r}")

    port = None
    if port_val is not None:
        # bool is an int subclass; reject it so `true` isn't read as port 1.
        if isinstance(port_val, bool) or not isinstance(port_val, int):
            raise PolicyError(f"{where} 'port' must be an integer")
        if not (1 <= port_val <= 65535):
            raise PolicyError(f"{where} 'port' must be between 1 and 65535")
        port = port_val

    source = _describe_rule(domain, ip_val if network is not None else None, port)
    return AllowRule(domain=domain, network=network, port=port, source=source)


def _try_network(value: str) -> Optional[IPNetwork]:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _validate_domain(value: str, where: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain:
        raise PolicyError(f"{where} domain is empty")
    body = domain[2:] if domain.startswith("*.") else domain
    if not body:
        raise PolicyError(f"{where} domain is empty after wildcard")
    if "*" in body:
        raise PolicyError(
            f"{where} domain wildcard is only supported as a leading '*.': {value!r}"
        )
    if not _DOMAIN_BODY_RE.fullmatch(body):
        raise PolicyError(f"{where} domain has invalid characters: {value!r}")
    return domain


def _describe_rule(domain: Optional[str], ip: Optional[str], port: Optional[int]) -> str:
    parts = []
    if domain:
        parts.append(domain)
    if ip:
        parts.append(ip)
    label = " ".join(parts) if parts else "?"
    return f"{label}:{port}" if port is not None else label


def resolve_destinations(
    events: List[EventSchema],
    domain_candidates: dict,
) -> List[dict]:
    """Collapse events into unique (ip, port) destinations with a primary domain.

    Mirrors the per-destination resolution in compute_aggregates so the verdict
    is consistent with the top-destinations table, but covers *every* destination
    rather than the displayed top 50.
    """
    dest_counter = Counter((event.dst_ip, event.dst_port) for event in events)

    proto_counters: dict = defaultdict(Counter)
    for event in events:
        proto_counters[(event.dst_ip, event.dst_port)][event.proto] += 1

    destinations = []
    for (ip, port), count in dest_counter.most_common():
        candidates = list(domain_candidates.get(ip, []))
        if not candidates:
            event_domain_counts = Counter(
                (event.domain, event.domain_source)
                for event in events
                if event.dst_ip == ip and event.domain
            )
            candidates = [
                DomainCandidate(domain=domain, source=source, count=candidate_count)
                for (domain, source), candidate_count in event_domain_counts.items()
                if source
            ]
        primary = choose_primary_domain(candidates) if candidates else None
        destinations.append({
            "dst_ip": ip,
            "dst_port": port,
            "proto": proto_counters[(ip, port)].most_common(1)[0][0],
            "count": count,
            "domain": primary.domain if primary else None,
        })
    return destinations


def evaluate_policy(
    policy: Policy,
    events: List[EventSchema],
    domain_candidates: dict,
) -> dict:
    """Judge every observed destination against the policy and return a verdict."""
    destinations = resolve_destinations(events, domain_candidates)

    unexpected = []
    expected_count = 0
    for dest in destinations:
        if policy.allows(dest["dst_ip"], dest["dst_port"], dest["domain"]):
            expected_count += 1
        else:
            unexpected.append(dest)

    unexpected.sort(key=lambda d: (-d["count"], d["dst_ip"], d["dst_port"]))

    return {
        "enabled": True,
        "verdict": "fail" if unexpected else "pass",
        "allow_rules": len(policy.rules),
        "expected_count": expected_count,
        "unexpected_count": len(unexpected),
        "unexpected": unexpected,
    }
