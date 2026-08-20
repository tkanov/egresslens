"""The event records the policy engine judges, and a strict loader for them.

The engine is fed pydantic ``EventSchema`` instances by the backend and ``Event``
instances here, so what it actually requires is a shape, not a class -- hence the
``EventLike`` protocol below.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Protocol


class EventLike(Protocol):
    """The five attributes the verdict path touches.

    ``policy`` reads ``dst_ip``/``dst_port``/``proto``/``domain``/
    ``domain_source``, and ``enrichment`` writes the last two. Nothing on the
    verdict path reads ``ts``, ``pid``, ``event``, ``family`` or ``result``, so
    naming a concrete class in those signatures would claim a dependency the
    engine does not have.
    """

    dst_ip: str
    dst_port: int
    proto: str
    domain: Optional[str]
    domain_source: Optional[str]


@dataclass
class Event:
    """One captured destination, carrying only what a verdict is computed from.

    Mutable because ``enrich_events`` assigns ``domain``/``domain_source`` in
    place. The fields the verdict never reads are deliberately absent: a verdict
    cannot come to depend on a field that does not exist here.
    """

    dst_ip: str
    dst_port: int
    proto: str = "unknown"
    domain: Optional[str] = None
    domain_source: Optional[str] = None


class EventsError(ValueError):
    """Raised when an events file cannot be read as a set of destinations."""


def load_events(path: Path) -> List[Event]:
    """Read ``egress.jsonl`` strictly, refusing any line it cannot interpret.

    This is deliberately harsher than ``metadata.count_events_from_jsonl``, which
    skips malformed lines: that function produces a count for display, this one
    decides a security verdict, so a line that cannot be parsed is an error
    rather than a silent omission from the set being judged.

    Only the five fields the verdict is computed from are validated. ``ts``,
    ``pid``, ``event``, ``family`` and ``result`` are not read at all -- failing
    a gate over a field that cannot change the answer buys nothing. In
    particular there is no filtering by ``result``: a connect that was refused
    still shows intent and still counts, which is what the backend does.

    The whole file is held in memory as events, the same profile as the upload
    path (which caps at 50 MB). No cap is imposed here: the file is one the
    caller produced locally, not an untrusted upload.
    """
    if not path.exists():
        raise EventsError(
            f"no events file at {path}; run a capture first, or point --events at one"
        )

    events: List[Event] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                events.append(_parse_event(stripped, path, line_number))
    except OSError as exc:
        raise EventsError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise EventsError(f"{path} is not valid UTF-8: {exc}") from exc

    return events


def _parse_event(line: str, path: Path, line_number: int) -> Event:
    where = f"{path}:{line_number}"
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise EventsError(f"{where}: not valid JSON: {exc.msg}") from exc
    if not isinstance(record, dict):
        raise EventsError(f"{where}: expected a JSON object, got {type(record).__name__}")

    dst_ip = record.get("dst_ip")
    if not isinstance(dst_ip, str) or not dst_ip:
        raise EventsError(f"{where}: 'dst_ip' must be a non-empty string")
    # No ipaddress validation on purpose: AllowRule._network_ok already treats an
    # unparseable address as no match, so a corrupt address fails closed instead
    # of being quietly allowed.

    dst_port = record.get("dst_port")
    # bool is an int subclass; reject it so `true` isn't read as port 1.
    if isinstance(dst_port, bool) or not isinstance(dst_port, int):
        raise EventsError(f"{where}: 'dst_port' must be an integer")
    if not (1 <= dst_port <= 65535):
        raise EventsError(f"{where}: 'dst_port' must be between 1 and 65535")

    proto = record.get("proto", "unknown")
    if not isinstance(proto, str):
        raise EventsError(f"{where}: 'proto' must be a string")

    # A null is read as absent, because that is how an already-enriched JSONL
    # writes "no domain attributed". A non-string that is not null would reach
    # domain_matches' .lower() and blow up mid-verdict.
    domain = _optional_string(record.get("domain"), "domain", where)
    domain_source = _optional_string(record.get("domain_source"), "domain_source", where)

    return Event(
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        domain=domain,
        domain_source=domain_source,
    )


def _optional_string(value: object, field: str, where: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EventsError(f"{where}: '{field}' must be a string or null")
    return value
