"""Domain enrichment for uploaded egress reports."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.schemas import EventSchema


PASSIVE_DNS_SOURCE = "passive_dns"
REVERSE_DNS_SOURCE = "reverse_dns"


@dataclass
class DomainCandidate:
    """A candidate domain observed for an IP address."""

    domain: str
    source: str
    count: int


@dataclass
class EnrichmentResult:
    """Domain enrichment output and upload summary counts."""

    domain_candidates: dict[str, list[DomainCandidate]] = field(default_factory=dict)
    passive_matches: int = 0
    reverse_matches: int = 0
    unresolved_ips: int = 0
    skipped_reverse_lookups: int = 0
    lookup_errors: int = 0

    def summary(self) -> dict:
        return {
            "passive_matches": self.passive_matches,
            "reverse_matches": self.reverse_matches,
            "unresolved_ips": self.unresolved_ips,
            "skipped_reverse_lookups": self.skipped_reverse_lookups,
            "lookup_errors": self.lookup_errors,
        }


Resolver = Callable[[str], tuple[str, list[str], list[str]]]


def empty_enrichment_summary() -> dict:
    """Return zeroed enrichment counters for disabled or empty uploads."""
    return EnrichmentResult().summary()


def enrich_events(
    events: list[EventSchema],
    strace_text: Optional[str],
    *,
    reverse_dns_enabled: bool,
    reverse_dns_timeout_seconds: float,
    reverse_dns_max_ips: int,
    resolver: Resolver = socket.gethostbyaddr,
) -> EnrichmentResult:
    """Populate event domain fields from passive DNS and bounded reverse DNS."""
    result = EnrichmentResult()
    if not events:
        return result

    passive_candidates = parse_passive_dns(strace_text or "")
    result.domain_candidates.update(passive_candidates)

    unique_ips = sorted({event.dst_ip for event in events})
    resolved_ips = set(passive_candidates.keys())
    result.passive_matches = len(resolved_ips.intersection(unique_ips))

    for event in events:
        candidates = passive_candidates.get(event.dst_ip)
        if candidates:
            primary = choose_primary_domain(candidates)
            event.domain = primary.domain
            event.domain_source = primary.source

    unresolved_for_reverse = [ip for ip in unique_ips if ip not in resolved_ips]
    if not reverse_dns_enabled:
        result.skipped_reverse_lookups = len(unresolved_for_reverse)
        result.unresolved_ips = len(unresolved_for_reverse)
        return result

    reverse_lookup_count = 0
    for ip in unresolved_for_reverse:
        if not is_public_ip(ip):
            result.skipped_reverse_lookups += 1
            continue
        if reverse_lookup_count >= reverse_dns_max_ips:
            result.skipped_reverse_lookups += 1
            continue

        reverse_lookup_count += 1
        domain = reverse_lookup(ip, reverse_dns_timeout_seconds, resolver)
        if domain:
            candidate = DomainCandidate(domain=domain, source=REVERSE_DNS_SOURCE, count=1)
            result.domain_candidates[ip] = [candidate]
            resolved_ips.add(ip)
            result.reverse_matches += 1
            for event in events:
                if event.dst_ip == ip:
                    event.domain = domain
                    event.domain_source = REVERSE_DNS_SOURCE
        else:
            result.lookup_errors += 1

    result.unresolved_ips = len([ip for ip in unique_ips if ip not in resolved_ips])
    return result


def parse_passive_dns(strace_text: str) -> dict[str, list[DomainCandidate]]:
    """Extract A-record answer mappings from DNS response payloads in strace text."""
    counts: dict[str, dict[str, int]] = {}
    for payload in extract_dns_payloads(strace_text):
        try:
            mappings = parse_dns_response(payload)
        except (ValueError, IndexError):
            continue
        for ip, domain in mappings:
            if not domain:
                continue
            domain_counts = counts.setdefault(ip, {})
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    return {
        ip: [
            DomainCandidate(domain=domain, source=PASSIVE_DNS_SOURCE, count=count)
            for domain, count in sorted(domain_counts.items())
        ]
        for ip, domain_counts in counts.items()
    }


def extract_dns_payloads(strace_text: str) -> list[bytes]:
    """Return decoded syscall string buffers that may contain DNS responses."""
    payloads: list[bytes] = []
    for line in strace_text.splitlines():
        if "recvfrom(" not in line and "recvmsg(" not in line:
            continue
        if " = -" in line:
            continue

        raw_buffers = []
        recvfrom_match = re.search(r"recvfrom\([^,]+,\s*\"((?:\\.|[^\"\\])*)\"", line)
        if recvfrom_match:
            raw_buffers.append(recvfrom_match.group(1))
        raw_buffers.extend(re.findall(r"iov_base=\"((?:\\.|[^\"\\])*)\"", line))

        for raw in raw_buffers:
            payloads.append(decode_strace_string(raw))
    return payloads


def decode_strace_string(value: str) -> bytes:
    """Decode strace's C-style escaped syscall string argument."""
    output = bytearray()
    i = 0
    while i < len(value):
        char = value[i]
        if char != "\\":
            output.extend(char.encode("latin1", errors="replace"))
            i += 1
            continue

        i += 1
        if i >= len(value):
            output.append(ord("\\"))
            break

        escaped = value[i]
        if escaped in {'\\', '"', "'"}:
            output.append(ord(escaped))
            i += 1
        elif escaped == "n":
            output.append(10)
            i += 1
        elif escaped == "r":
            output.append(13)
            i += 1
        elif escaped == "t":
            output.append(9)
            i += 1
        elif escaped == "x":
            hex_digits = value[i + 1 : i + 3]
            if len(hex_digits) == 2 and all(c in "0123456789abcdefABCDEF" for c in hex_digits):
                output.append(int(hex_digits, 16))
                i += 3
            else:
                output.append(ord("x"))
                i += 1
        elif escaped in "01234567":
            digits = escaped
            i += 1
            for _ in range(2):
                if i < len(value) and value[i] in "01234567":
                    digits += value[i]
                    i += 1
                else:
                    break
            output.append(int(digits, 8))
        else:
            output.append(ord(escaped))
            i += 1
    return bytes(output)


def parse_dns_response(payload: bytes) -> list[tuple[str, str]]:
    """Parse A-record answers from a DNS response payload."""
    if len(payload) < 12:
        raise ValueError("DNS payload is too short")

    flags = int.from_bytes(payload[2:4], "big")
    if not flags & 0x8000:
        return []

    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    offset = 12
    question_names: list[str] = []

    for _ in range(qdcount):
        name, offset = read_dns_name(payload, offset)
        question_names.append(name)
        offset = require_length(payload, offset, 4)

    mappings: list[tuple[str, str]] = []
    fallback_name = question_names[0] if question_names else ""
    for _ in range(ancount):
        name, offset = read_dns_name(payload, offset)
        header_end = require_length(payload, offset, 10)
        record_type = int.from_bytes(payload[offset : offset + 2], "big")
        record_class = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        rdlength = int.from_bytes(payload[offset + 8 : offset + 10], "big")
        offset = header_end
        end = require_length(payload, offset, rdlength)

        if record_type == 1 and record_class == 1 and rdlength == 4:
            ip = str(ipaddress.IPv4Address(payload[offset:end]))
            mappings.append((ip, name or fallback_name))
        offset = end

    return mappings


def read_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Read a possibly compressed DNS name."""
    labels: list[str] = []
    original_offset = offset
    jumped = False
    jumps = 0

    while True:
        if offset >= len(payload):
            raise ValueError("DNS name exceeds payload length")
        length = payload[offset]

        if length & 0xC0 == 0xC0:
            require_length(payload, offset, 2)
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer >= len(payload):
                raise ValueError("DNS compression pointer exceeds payload length")
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > 16:
                raise ValueError("DNS compression pointer loop")
            continue

        if length & 0xC0:
            raise ValueError("Unsupported DNS label type")

        offset += 1
        if length == 0:
            break

        end = require_length(payload, offset, length)
        labels.append(payload[offset:end].decode("ascii", errors="ignore").lower())
        offset = end

    return ".".join(label for label in labels if label), original_offset if jumped else offset


def require_length(payload: bytes, offset: int, length: int) -> int:
    end = offset + length
    if end > len(payload):
        raise ValueError("DNS record exceeds payload length")
    return end


def choose_primary_domain(candidates: list[DomainCandidate]) -> DomainCandidate:
    """Select one primary domain, preferring passive DNS and then observed count."""
    return sorted(
        candidates,
        key=lambda candidate: (
            0 if candidate.source == PASSIVE_DNS_SOURCE else 1,
            -candidate.count,
            candidate.domain,
        ),
    )[0]


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.version == 4
        and ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
    )


def reverse_lookup(
    ip: str,
    timeout_seconds: float,
    resolver: Resolver,
) -> Optional[str]:
    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        hostname, _, _ = resolver(ip)
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)

    return hostname.rstrip(".").lower() if hostname else None
