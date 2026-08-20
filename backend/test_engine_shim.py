#!/usr/bin/env python3
"""The policy engine the backend runs must be the one the CLI runs.

`app.policy` and `app.enrichment` are re-export shims over `egresslens.*`. These
tests fail if someone re-adds a local copy of either module, which would let the
upload verdict and `egresslens check` drift apart silently -- both would still
pass their own suites.

The last test guards the other half of that claim. A shared engine is not a
shared verdict if the two surfaces disagree about which files they will read at
all, and only this suite can compare them: the CLI's own tests cannot import
pydantic.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest

import app.enrichment as backend_enrichment
import app.policy as backend_policy
import egresslens.enrichment as cli_enrichment
import egresslens.policy as cli_policy
from app.schemas import EventSchema
from egresslens.events import EventLike, EventsError, load_events


def test_policy_shim_re_exports_the_cli_engine():
    for name in ("evaluate_policy", "load_policy", "resolve_destinations", "PolicyError"):
        assert getattr(backend_policy, name) is getattr(cli_policy, name), name


def test_enrichment_shim_re_exports_the_cli_engine():
    for name in ("enrich_events", "event_domain_candidates", "choose_primary_domain"):
        assert getattr(backend_enrichment, name) is getattr(cli_enrichment, name), name


def test_event_schema_satisfies_the_engine_protocol():
    """The five attributes the engine reads and writes must exist on EventSchema."""
    assert set(EventLike.__annotations__) <= set(EventSchema.model_fields)


# Any field given this value is left out of the record, which is how the tables
# below say "absent".
_DROP = "__drop__"

BASE_EVENT = {
    "ts": 1.0,
    "pid": 1,
    "event": "connect",
    "family": "inet",
    "proto": "tcp",
    "dst_ip": "1.2.3.4",
    "dst_port": 443,
    "result": "ok",
}

# Values on the five fields the verdict is computed from. Each must be read the
# same way by both surfaces, whether that is "accepted" or "refused".
SHARED_CASES = [
    ("dst_port int", {"dst_port": 443}),
    ("dst_port numeric string", {"dst_port": "443"}),
    ("dst_port integral float", {"dst_port": 443.0}),
    ("dst_port fractional float", {"dst_port": 443.5}),
    ("dst_port zero", {"dst_port": 0}),
    ("dst_port above 65535", {"dst_port": 65536}),
    ("dst_port negative", {"dst_port": -1}),
    ("dst_port bool", {"dst_port": True}),
    ("dst_port null", {"dst_port": None}),
    ("dst_port absent", {"dst_port": _DROP}),
    ("dst_ip empty string", {"dst_ip": ""}),
    ("dst_ip not a string", {"dst_ip": 5}),
    ("dst_ip absent", {"dst_ip": _DROP}),
    ("domain null", {"domain": None}),
    ("domain not a string", {"domain": 17}),
]

# The two documented asymmetries, both looser here, neither able to change a
# verdict: the engine never reads these fields, and proto only selects a label.
LOOSER_IN_THE_CLI = [
    ("proto absent", {"proto": _DROP}),
    ("ts, pid and result absent", {"ts": _DROP, "pid": _DROP, "result": _DROP}),
]


def _record(patch: dict) -> dict:
    record = dict(BASE_EVENT, **patch)
    return {key: value for key, value in record.items() if value != _DROP}


def _upload_reads_it(record: dict) -> bool:
    try:
        EventSchema(**record)
    except Exception:
        return False
    return True


def _check_reads_it(record: dict, tmp_path: Path) -> bool:
    path = tmp_path / "egress.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    try:
        load_events(path)
    except EventsError:
        return False
    return True


@pytest.mark.parametrize("label,patch", SHARED_CASES, ids=[c[0] for c in SHARED_CASES])
def test_both_surfaces_read_the_same_event_files(label, patch, tmp_path):
    record = _record(patch)
    assert _upload_reads_it(record) == _check_reads_it(record, tmp_path), label


@pytest.mark.parametrize(
    "label,patch", LOOSER_IN_THE_CLI, ids=[c[0] for c in LOOSER_IN_THE_CLI]
)
def test_the_documented_asymmetries_are_the_only_ones(label, patch, tmp_path):
    """If either of these starts agreeing, docs/policy.md is overstating the gap."""
    record = _record(patch)
    assert not _upload_reads_it(record), label
    assert _check_reads_it(record, tmp_path), label


def main():
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
