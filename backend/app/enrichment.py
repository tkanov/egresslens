"""Domain enrichment: re-exported from egresslens.enrichment, where it now lives.

It moved with the policy engine it feeds, for the reason given in `app.policy`:
`egresslens check` needs the same domain attribution the upload path uses, and
the CLI cannot import from here. This module keeps `app.enrichment` importable,
and is a compatibility seam only: no logic belongs here.
"""
try:
    from egresslens.enrichment import (  # the egresslens CLI package is a backend dependency
        PASSIVE_DNS_SOURCE,
        REVERSE_DNS_SOURCE,
        DomainCandidate,
        EnrichmentResult,
        Resolver,
        choose_primary_domain,
        decode_strace_string,
        empty_enrichment_summary,
        enrich_events,
        event_domain_candidates,
        extract_dns_payloads,
        is_public_ip,
        parse_dns_response,
        parse_passive_dns,
        read_dns_name,
        require_length,
        reverse_lookup,
    )
except ImportError as exc:  # pragma: no cover - install-time failure, not a code path
    raise ImportError(
        "the egresslens CLI package provides domain enrichment; install it with "
        "`pip install -e ./cli` from the repo root"
    ) from exc

__all__ = [
    "PASSIVE_DNS_SOURCE",
    "REVERSE_DNS_SOURCE",
    "DomainCandidate",
    "EnrichmentResult",
    "Resolver",
    "choose_primary_domain",
    "decode_strace_string",
    "empty_enrichment_summary",
    "enrich_events",
    "event_domain_candidates",
    "extract_dns_payloads",
    "is_public_ip",
    "parse_dns_response",
    "parse_passive_dns",
    "read_dns_name",
    "require_length",
    "reverse_lookup",
]
