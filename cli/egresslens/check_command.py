"""Judge captured artifacts against an egress allowlist, as a CI gate.

Runs the same engine the backend runs on upload, against files on disk: no
server, no database, no Docker. The verdict is the exit code, so this is the half
of the tool that can fail a build.
"""
from __future__ import annotations

import json
import socket
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from egresslens.enrichment import Resolver, enrich_events
from egresslens.events import EventsError, load_events
from egresslens.policy import (
    Policy,
    PolicyError,
    evaluate_policy,
    load_policy,
    resolve_destinations,
)

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_INCONCLUSIVE = 3

# Keyed by the engine's own verdict strings so the mapping cannot drift from
# evaluate_policy: a new verdict would raise a KeyError here rather than being
# quietly reported as a pass.
VERDICT_EXIT_CODES = {
    "pass": EXIT_PASS,
    "fail": EXIT_FAIL,
    "inconclusive": EXIT_INCONCLUSIVE,
}

# Bumped only for a breaking change to the --format json payload; adding a key is
# not breaking.
SCHEMA_VERSION = 1

# The names a capture writes, as this command expects to find them. Named here
# because `main` needs the events name too, to tell "no capture happened" from
# "a capture happened and there is a verdict to reach".
EVENTS_FILENAME = "egress.jsonl"
STRACE_FILENAME = "egress.strace"
RUN_METADATA_FILENAME = "run.json"

# Rows printed before the list is elided. The engine caps the list it returns at
# MAX_UNEXPECTED (50), so the remainder disclosed against the exact
# unexpected_count can be larger than the number of rows that were available.
MAX_PRINTED_UNEXPECTED = 20

# Same wording as the backend's markdown export, so the two surfaces read alike.
INCONCLUSIVE_NOTE = (
    "No destinations were observed, so nothing was checked against the allowlist. "
    "This is not a pass: an empty capture, the wrong file, and a run that genuinely "
    "reached nothing all look the same here."
)
DOMAIN_ADVISORY_NOTE = (
    "Domain rules are advisory: the matched domain is attributed from the traced "
    "process's own DNS traffic and could be forged by an evading subject. ip/CIDR "
    "rules are the hard gate."
)
BLIND_SPOT_NOTE = (
    "This allowlist has domain rules, but not one destination carried an attributed "
    "domain, so every domain rule was dead and the result says more about the "
    "artifacts than about the app: no egress.strace was read, and the events carried "
    "no domain/domain_source of their own. Capture egress.strace alongside "
    "egress.jsonl, or pass --strace."
)


def _reverse_dns_note(matches: int) -> str:
    return (
        f"{matches} destination name(s) came from live reverse DNS lookups rather than "
        "from the trace, so the same artifacts can yield a different verdict on a "
        "re-run. Drop --reverse-dns for a reproducible gate."
    )


def write_line(stream, text: str) -> None:
    """Print a line, escaping whatever the stream's encoding cannot represent.

    Python already gives stderr ``errors="backslashreplace"`` for this reason and
    leaves stdout strict, so one non-ASCII character raises UnicodeEncodeError
    there -- and for a gate that is a traceback and exit 1, which is the FAIL
    code. That is the same collision the ASCII verdict line was chosen to avoid,
    reintroduced through three fields this command does not control: the output
    directory's path, the allowlist's path, and a destination's domain, which is
    attributed from the traced process's own DNS traffic. Measured with
    PYTHONIOENCODING=ascii, a passing capture in a directory named ``café``
    exited 1.

    Adaptive rather than always-ASCII: a UTF-8 console still shows the real name,
    and only a console that cannot gets ``\\xe9``. Re-escaping already-escaped
    text is a no-op, so this is safe on stderr too.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    safe = text.encode(encoding, errors="backslashreplace").decode(encoding, errors="replace")
    print(safe, file=stream)


class CheckInputError(Exception):
    """An input could not be read, decoded, or parsed.

    Deliberately not a click.ClickException: click exits 1 for those, and 1 is
    the FAIL code, which would make "your policy file is broken" indistinguishable
    from "your policy was violated". Everything raised here becomes EXIT_ERROR.
    """


@dataclass
class CheckResult:
    """Everything both output formats render, computed once."""

    verdict: str
    exit_code: int
    policy: dict
    events_path: Path
    event_count: int
    strace_path: Optional[Path]
    expected_via_ip: int
    expected_via_domain_only: int
    enrichment: dict
    notes: List[str] = field(default_factory=list)


def resolve_artifacts(
    directory: Path,
    events_path: Optional[Path] = None,
    strace_path: Optional[Path] = None,
) -> tuple[Path, Optional[Path]]:
    """Decide which files to read, and whether a missing one is an error.

    A missing events file is reported by load_events, which names it. A trace is
    different depending on how it was named: asked for explicitly and missing is
    an error, while a capture that simply has no egress.strace is ordinary and
    only means no passive DNS.
    """
    resolved_events = events_path if events_path is not None else directory / EVENTS_FILENAME

    if strace_path is not None:
        if not strace_path.exists():
            raise CheckInputError(f"no trace file at {strace_path}")
        return resolved_events, strace_path

    # Beside the events, not beside DIRECTORY. With --events pointing at another
    # layout, DIRECTORY is still whatever it defaulted to, so an unrelated
    # egresslens-output/egress.strace left in the working directory would
    # otherwise attribute one capture's DNS answers to another capture's events
    # -- enough to turn a domain rule into a PASS it never earned. A capture
    # writes both files into one directory, so this is the same path in the
    # ordinary case.
    default_strace = resolved_events.parent / STRACE_FILENAME
    return resolved_events, default_strace if default_strace.exists() else None


def load_policy_file(path: Path) -> Policy:
    """Read and parse an allowlist, turning every failure into a CheckInputError.

    Catches what the upload endpoint catches, for the same reasons: RecursionError
    comes from deeply nested JSON, and a policy that cannot be read must not be
    reported as a policy that was violated.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CheckInputError(f"cannot read policy {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise CheckInputError(f"policy {path} is not UTF-8: {exc}") from exc
    except RecursionError as exc:
        raise CheckInputError(f"policy {path} is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        raise CheckInputError(f"policy {path} is not valid JSON: {exc}") from exc

    try:
        return load_policy(data)
    except PolicyError as exc:
        raise CheckInputError(f"invalid policy {path}: {exc}") from exc


def read_strace(path: Path) -> str:
    """Read a trace as lossy UTF-8, as the upload path does.

    A trace is a byte log of a foreign process's buffers, so one undecodable byte
    must not cost us the DNS answers around it.
    """
    try:
        return path.read_bytes().decode("utf-8", errors="ignore")
    except OSError as exc:
        raise CheckInputError(f"cannot read trace {path}: {exc}") from exc


def evaluate_capture(
    directory: Path,
    policy_path: Path,
    events_path: Optional[Path] = None,
    strace_path: Optional[Path] = None,
    *,
    reverse_dns: bool = False,
    reverse_dns_timeout: float = 0.5,
    reverse_dns_max_ips: int = 100,
    resolver: Resolver = socket.gethostbyaddr,
) -> CheckResult:
    """Enrich, judge, and measure how much of the verdict rests on domain names."""
    resolved_events, resolved_strace = resolve_artifacts(directory, events_path, strace_path)
    policy = load_policy_file(policy_path)
    events = load_events(resolved_events)
    strace_text = read_strace(resolved_strace) if resolved_strace is not None else None

    enrichment = enrich_events(
        events,
        strace_text,
        reverse_dns_enabled=reverse_dns,
        reverse_dns_timeout_seconds=reverse_dns_timeout,
        reverse_dns_max_ips=reverse_dns_max_ips,
        resolver=resolver,
    )
    verdict = evaluate_policy(policy, events, enrichment.domain_candidates)

    # A second offline pass over the events: evaluate_policy resolves the same
    # destinations but does not return them, and the split below is what turns
    # "PASS" into "PASS, with N destinations resting on a forgeable name". By the
    # engine's own measurement the whole pass is 0.39s for a report at the 50 MB
    # upload cap, so this costs about that again -- cheaper than widening the
    # engine's signature for one caller.
    destinations = resolve_destinations(events, enrichment.domain_candidates)
    expected_via_ip = 0
    expected_via_domain_only = 0
    for dest in destinations:
        if not policy.allows(dest["dst_ip"], dest["dst_port"], dest["domains"]):
            continue
        # The empty domain list is the hard-gate probe, not an oversight: with no
        # domains to offer, Policy.allows can only return True from a pure
        # ip/CIDR rule. Anything else is expected on the strength of a name.
        if policy.allows(dest["dst_ip"], dest["dst_port"], []):
            expected_via_ip += 1
        else:
            expected_via_domain_only += 1

    enrichment_summary = enrichment.summary()
    enrichment_summary["reverse_dns_enabled"] = reverse_dns

    return CheckResult(
        verdict=verdict["verdict"],
        exit_code=VERDICT_EXIT_CODES[verdict["verdict"]],
        # evaluate_policy's dict verbatim, plus where the allowlist came from. No
        # translation layer, so the JSON output cannot drift from the engine or
        # from what the UI shows for the same artifacts.
        policy=dict({"path": str(policy_path)}, **verdict),
        events_path=resolved_events,
        event_count=len(events),
        strace_path=resolved_strace,
        expected_via_ip=expected_via_ip,
        expected_via_domain_only=expected_via_domain_only,
        enrichment=enrichment_summary,
        notes=build_notes(verdict, destinations, enrichment.reverse_matches),
    )


def build_notes(verdict: dict, destinations: List[dict], reverse_matches: int) -> List[str]:
    """Say what the verdict does not: what it rests on, and where it is blind."""
    notes = []
    if verdict["verdict"] == "inconclusive":
        notes.append(INCONCLUSIVE_NOTE)
    if verdict["has_domain_rules"]:
        notes.append(DOMAIN_ADVISORY_NOTE)
        # Tested as an outcome rather than as "was there a trace file": an
        # egress.jsonl can carry its own attribution, which is what
        # event_domain_candidates exists for, so the question is whether any
        # destination ended up named at all. Skipped when there is nothing to
        # judge, because the inconclusive note already says so.
        if destinations and not any(dest["domains"] for dest in destinations):
            notes.append(BLIND_SPOT_NOTE)
    if reverse_matches:
        notes.append(_reverse_dns_note(reverse_matches))
    return notes


def render_text(result: CheckResult) -> str:
    """Render the human report.

    The verdict line is deliberately ASCII, unlike the capture commands' output:
    a check/cross glyph on a non-UTF-8 console raises UnicodeEncodeError, and for
    a gate that means a traceback and exit 1, which reads as FAIL.
    """
    policy = result.policy
    lines = [
        f"Egress policy: {result.verdict.upper()}",
        f"  Allowlist: {policy['path']} ({policy['allow_rules']} rules)",
        f"  Events: {result.event_count} from {result.events_path}",
        f"  Destinations evaluated: {policy['destinations_evaluated']} "
        f"({policy['expected_count']} expected, {policy['unexpected_count']} unexpected)",
        f"  Expected via ip/CIDR rule: {result.expected_via_ip}",
        f"  Expected via domain rule only: {result.expected_via_domain_only} (advisory)",
    ]

    printed = policy["unexpected"][:MAX_PRINTED_UNEXPECTED]
    if printed:
        lines.append("")
        lines.append("  Unexpected destinations:")
        lines.extend(_unexpected_rows(printed))
        remaining = policy["unexpected_count"] - len(printed)
        if remaining > 0:
            lines.append(f"    ... and {remaining} more not shown.")

    for note in result.notes:
        lines.append("")
        lines.append(
            textwrap.fill(note, width=78, initial_indent="  Note: ", subsequent_indent="  ")
        )
    return "\n".join(lines)


def _unexpected_rows(rows: List[dict]) -> List[str]:
    counts = [str(row["count"]) for row in rows]
    domains = [row["domain"] or "-" for row in rows]
    endpoints = [f"{row['dst_ip']}:{row['dst_port']}" for row in rows]
    count_width = max(len(value) for value in counts)
    domain_width = max(len(value) for value in domains)
    endpoint_width = max(len(value) for value in endpoints)
    return [
        f"    {count:>{count_width}}  {domain:<{domain_width}}  "
        f"{endpoint:<{endpoint_width}}  {row['proto']}"
        for count, domain, endpoint, row in zip(counts, domains, endpoints, rows)
    ]


def render_json(result: CheckResult) -> str:
    """Render the machine report. Nothing else may go to stdout in this mode."""
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            # Duplicated from policy for `jq -e '.verdict == "pass"'` ergonomics.
            "verdict": result.verdict,
            "exit_code": result.exit_code,
            "policy": result.policy,
            "expected_via_ip": result.expected_via_ip,
            "expected_via_domain_only": result.expected_via_domain_only,
            "events": {"path": str(result.events_path), "count": result.event_count},
            "strace": {
                "path": str(result.strace_path) if result.strace_path is not None else None,
                "present": result.strace_path is not None,
            },
            "enrichment": result.enrichment,
            "notes": result.notes,
        },
        indent=2,
    )


def check_command(
    directory: Path,
    policy_path: Path,
    events_path: Optional[Path] = None,
    strace_path: Optional[Path] = None,
    *,
    reverse_dns: bool = False,
    reverse_dns_timeout: float = 0.5,
    reverse_dns_max_ips: int = 100,
    output_format: str = "text",
    resolver: Resolver = socket.gethostbyaddr,
) -> int:
    """Evaluate a capture against an allowlist and return the gate's exit code.

    0 pass, 1 fail, 2 error, 3 inconclusive. An input problem is 2 and never 1,
    so a broken allowlist can never be mistaken for a violated one.

    ``resolver`` is not exposed as a flag; it exists so tests can prove no PTR
    lookup happens unless --reverse-dns is passed, mirroring the injection
    enrich_events already offers.
    """
    try:
        result = evaluate_capture(
            directory,
            policy_path,
            events_path,
            strace_path,
            reverse_dns=reverse_dns,
            reverse_dns_timeout=reverse_dns_timeout,
            reverse_dns_max_ips=reverse_dns_max_ips,
            resolver=resolver,
        )
    except (CheckInputError, EventsError) as exc:
        # Only these two. A genuine bug should still traceback rather than be
        # reported as somebody's malformed input.
        write_line(sys.stderr, f"Error: {exc}")
        return EXIT_ERROR

    write_line(sys.stdout, render_json(result) if output_format == "json" else render_text(result))
    return result.exit_code
