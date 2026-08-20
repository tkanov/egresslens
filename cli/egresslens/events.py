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
    """Read ``egress.jsonl``, refusing only what cannot be read as a destination.

    Two rules, and the difference between them is what this loader is about.

    *A line that cannot be read is an error*, not a skip. That is deliberately
    harsher than ``metadata.count_events_from_jsonl``, which continues past
    malformed lines: that function produces a count for display, this one decides
    a security verdict, so a line it cannot interpret must not be quietly dropped
    out of the set being judged.

    *A value that can be read is read*, and is not second-guessed. Every accepted
    field here is accepted by the upload endpoint too, coercions included (see
    ``_coerce_port``), because the two surfaces are documented as reaching the
    same verdict from the same artifacts. A stricter loader breaks that in the
    worst available direction: refusing the file converts a real FAIL into an
    exit-2 error that names a field instead of the destination.

    Two deliberate asymmetries, both looser than the upload path, neither able to
    change a verdict:

    - ``ts``, ``pid``, ``event``, ``family`` and ``result`` are not read at all,
      where ``EventSchema`` requires them. The engine reads five attributes and
      those are not among them. In particular there is no filtering by
      ``result``: a connect that was refused still shows intent and still counts,
      which is what the backend does with it too.
    - ``proto`` defaults to ``"unknown"`` when absent, where ``EventSchema``
      requires it. It selects the protocol label displayed for a destination and
      is never matched against a rule.

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

    if "dst_ip" not in record:
        raise EventsError(f"{where}: no 'dst_ip'")
    dst_ip = record["dst_ip"]
    if not isinstance(dst_ip, str):
        raise EventsError(f"{where}: 'dst_ip' must be a string")
    # Not validated as an address, and the empty string is not rejected either.
    # AllowRule._network_ok treats anything unparseable as no match, so a corrupt
    # address can only ever be reported unexpected -- it fails closed without the
    # loader having to refuse the whole file, which is the outcome that would hide
    # the rest of the capture.

    if "dst_port" not in record:
        raise EventsError(f"{where}: no 'dst_port'")
    dst_port = _coerce_port(record["dst_port"], where)

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


def _coerce_port(value: object, where: str) -> int:
    """Read an observed port as permissively as the upload path reads it.

    Pydantic's lax mode gives ``EventSchema.dst_port`` an int from an int, a
    bool, an integral float or a numeric string, and imposes no range, so the
    backend produces a verdict for all of those. This mirrors that list rather
    than narrowing it, because the two surfaces claim to agree on a verdict for
    the same artifacts, and the only way this loader can disagree is by refusing
    to produce one at all.

    Note the asymmetry with a *rule* port, which `policy.py` bounds to 1..65535
    and where a bool is rejected outright. That is the right rule there and the
    wrong rule here: a rule port is declared by a human, so `true` is a typo that
    must fail loudly, while an observed port is whatever the kernel was handed
    and the loader's job is to report it, not to grade it. Getting this backwards
    made the gate unusable on ordinary captures -- glibc's RFC 3484 address
    sorting connect()s to ``sin_port=htons(0)``, so a 1..65535 floor rejected the
    whole file for any app that resolved a hostname, and a traced app could bury
    a real violation behind one connect() to port 0.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise EventsError(f"{where}: 'dst_port' {value!r} is not a whole number")
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            raise EventsError(f"{where}: 'dst_port' {value!r} is not a number") from None
    raise EventsError(f"{where}: 'dst_port' must be a number, not {type(value).__name__}")


def _optional_string(value: object, field: str, where: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EventsError(f"{where}: '{field}' must be a string or null")
    return value
