#!/usr/bin/env python3
"""Tests for backend domain enrichment."""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import socket

from app.config import load_config
from app.enrichment import enrich_events, parse_passive_dns, reverse_lookup
from app.schemas import EventSchema


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def dns_response(question: str, answers: list[tuple[str, str]]) -> bytes:
    question_bytes = dns_name(question) + b"\x00\x01\x00\x01"
    answer_bytes = b""
    for name, ip in answers:
        answer_name = b"\xc0\x0c" if name == question else dns_name(name)
        answer_bytes += (
            answer_name
            + b"\x00\x01\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + bytes(int(part) for part in ip.split("."))
        )
    return (
        b"\x12\x34\x81\x80"
        + b"\x00\x01"
        + len(answers).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + question_bytes
        + answer_bytes
    )


def strace_escape(payload: bytes) -> str:
    escaped = []
    for byte in payload:
        char = chr(byte)
        if byte == 92:
            escaped.append("\\\\")
        elif byte == 34:
            escaped.append('\\"')
        elif 32 <= byte <= 126:
            escaped.append(char)
        else:
            escaped.append(f"\\{byte:03o}")
    return "".join(escaped)


def strace_recv_line(payload: bytes) -> str:
    return (
        '123 1707150823.500 recvfrom(4, "'
        + strace_escape(payload)
        + '", 512, 0, {sa_family=AF_INET, sin_port=htons(53), '
        + 'sin_addr=inet_addr("8.8.8.8")}, [28 => 16]) = '
        + str(len(payload))
    )


def event(ip: str, port: int = 443) -> EventSchema:
    return EventSchema(
        ts=1.0,
        pid=100,
        event="connect",
        family="inet",
        proto="tcp",
        dst_ip=ip,
        dst_port=port,
        result="ok",
    )


def test_passive_dns_maps_a_record():
    payload = dns_response("example.com", [("example.com", "93.184.216.34")])
    candidates = parse_passive_dns(strace_recv_line(payload))
    assert candidates["93.184.216.34"][0].domain == "example.com"
    assert candidates["93.184.216.34"][0].count == 1
    print("passive DNS maps A record")


def test_passive_dns_counts_repeated_names_and_ignores_malformed():
    example = dns_response("example.com", [("example.com", "93.184.216.34")])
    alias = dns_response("www.example.com", [("www.example.com", "93.184.216.34")])
    strace_text = "\n".join([
        strace_recv_line(example),
        strace_recv_line(example),
        strace_recv_line(alias),
        '123 1.0 recvfrom(4, "\\001\\002", 512, 0, NULL, NULL) = 2',
        'not strace at all',
    ])
    candidates = parse_passive_dns(strace_text)["93.184.216.34"]
    counts = {candidate.domain: candidate.count for candidate in candidates}
    assert counts == {"example.com": 2, "www.example.com": 1}
    print("passive DNS counts repeated names and ignores malformed payloads")


def test_passive_dns_takes_precedence_over_reverse_dns():
    events = [event("93.184.216.34")]
    payload = dns_response("example.com", [("example.com", "93.184.216.34")])

    def resolver(ip: str):
        return ("reverse.example", [], [ip])

    result = enrich_events(
        events,
        strace_recv_line(payload),
        reverse_dns_enabled=True,
        reverse_dns_timeout_seconds=0.01,
        reverse_dns_max_ips=100,
        resolver=resolver,
    )
    assert events[0].domain == "example.com"
    assert events[0].domain_source == "passive_dns"
    assert result.passive_matches == 1
    assert result.reverse_matches == 0
    print("passive DNS takes precedence over reverse DNS")


def test_reverse_dns_fallback_and_private_skip():
    events = [event("8.8.8.8"), event("192.168.1.10")]
    called = []

    def resolver(ip: str):
        called.append(ip)
        return ("dns.google", [], [ip])

    result = enrich_events(
        events,
        "",
        reverse_dns_enabled=True,
        reverse_dns_timeout_seconds=0.01,
        reverse_dns_max_ips=100,
        resolver=resolver,
    )
    assert called == ["8.8.8.8"]
    assert events[0].domain == "dns.google"
    assert events[0].domain_source == "reverse_dns"
    assert events[1].domain is None
    assert result.reverse_matches == 1
    assert result.skipped_reverse_lookups == 1
    print("reverse DNS resolves public IPs and skips private IPs")


def test_reverse_dns_max_ips():
    events = [event("8.8.8.8"), event("1.1.1.1")]

    def resolver(ip: str):
        return (f"ptr-{ip}.example", [], [ip])

    result = enrich_events(
        events,
        "",
        reverse_dns_enabled=True,
        reverse_dns_timeout_seconds=0.01,
        reverse_dns_max_ips=1,
        resolver=resolver,
    )
    assert result.reverse_matches == 1
    assert result.skipped_reverse_lookups == 1
    print("reverse DNS max lookup cap is enforced")


def test_reverse_lookup_restores_default_timeout():
    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(None)

        # Success path must not leak the temporary lookup timeout.
        result = reverse_lookup("8.8.8.8", 0.01, lambda ip: ("dns.google", [], [ip]))
        assert result == "dns.google"
        assert socket.getdefaulttimeout() is None

        # Failure path (caught resolver error) must also restore the default.
        def boom(ip):
            raise socket.herror("nope")

        assert reverse_lookup("8.8.8.8", 0.01, boom) is None
        assert socket.getdefaulttimeout() is None
    finally:
        socket.setdefaulttimeout(original)
    print("reverse DNS restores the global default timeout")


def test_config_defaults_and_env_overrides():
    names = [
        "ENRICHMENT_ENABLED",
        "ENRICHMENT_REVERSE_DNS_ENABLED",
        "ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS",
        "ENRICHMENT_REVERSE_DNS_MAX_IPS",
    ]
    original = {name: os.environ.get(name) for name in names}
    try:
        for name in names:
            os.environ.pop(name, None)
        defaults = load_config().enrichment
        assert defaults.enabled is True
        assert defaults.reverse_dns_enabled is True
        assert defaults.reverse_dns_timeout_seconds == 0.5
        assert defaults.reverse_dns_max_ips == 100

        os.environ["ENRICHMENT_ENABLED"] = "false"
        os.environ["ENRICHMENT_REVERSE_DNS_ENABLED"] = "no"
        os.environ["ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS"] = "1.25"
        os.environ["ENRICHMENT_REVERSE_DNS_MAX_IPS"] = "7"
        overridden = load_config().enrichment
        assert overridden.enabled is False
        assert overridden.reverse_dns_enabled is False
        assert overridden.reverse_dns_timeout_seconds == 1.25
        assert overridden.reverse_dns_max_ips == 7
    finally:
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    print("config defaults and environment overrides work")


def main():
    test_passive_dns_maps_a_record()
    test_passive_dns_counts_repeated_names_and_ignores_malformed()
    test_passive_dns_takes_precedence_over_reverse_dns()
    test_reverse_dns_fallback_and_private_skip()
    test_reverse_dns_max_ips()
    test_reverse_lookup_restores_default_timeout()
    test_config_defaults_and_env_overrides()
    print("all enrichment tests passed")


if __name__ == "__main__":
    main()
