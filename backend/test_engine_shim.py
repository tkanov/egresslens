#!/usr/bin/env python3
"""The policy engine the backend runs must be the one the CLI runs.

`app.policy` and `app.enrichment` are re-export shims over `egresslens.*`. These
tests fail if someone re-adds a local copy of either module, which would let the
upload verdict and `egresslens check` drift apart silently -- both would still
pass their own suites.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import app.enrichment as backend_enrichment
import app.policy as backend_policy
import egresslens.enrichment as cli_enrichment
import egresslens.policy as cli_policy
from app.schemas import EventSchema
from egresslens.events import EventLike


def test_policy_shim_re_exports_the_cli_engine():
    for name in ("evaluate_policy", "load_policy", "resolve_destinations", "PolicyError"):
        assert getattr(backend_policy, name) is getattr(cli_policy, name), name


def test_enrichment_shim_re_exports_the_cli_engine():
    for name in ("enrich_events", "event_domain_candidates", "choose_primary_domain"):
        assert getattr(backend_enrichment, name) is getattr(cli_enrichment, name), name


def test_event_schema_satisfies_the_engine_protocol():
    """The five attributes the engine reads and writes must exist on EventSchema."""
    assert set(EventLike.__annotations__) <= set(EventSchema.model_fields)


def main():
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
