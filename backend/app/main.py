"""FastAPI application for EgressLens backend."""
import uuid
import json
import re
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import init_db, get_db
from app.models import Report
from app.schemas import EventSchema, ReportUploadResponse, ReportResponse
from app.config import settings
from app.enrichment import (
    DomainCandidate,
    choose_primary_domain,
    empty_enrichment_summary,
    enrich_events,
)
from app.policy import PolicyError, evaluate_policy, load_policy

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup (replaces the deprecated on_event hook)."""
    init_db()
    yield


app = FastAPI(
    title="EgressLens API",
    description="API for uploading and analyzing network egress monitoring data",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
# Allow requests from Vite dev server and common forwarded ports
# For dev containers with custom forwarded ports, set ALLOWED_ORIGINS env var
import os
allowed_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# Allow additional origins via environment variable (comma-separated)
# Example: ALLOWED_ORIGINS="http://localhost:8080,http://127.0.0.1:8080"
if os.getenv("ALLOWED_ORIGINS"):
    allowed_origins.extend([origin.strip() for origin in os.getenv("ALLOWED_ORIGINS").split(",")])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Load configuration (including flag thresholds)
# These can be overridden via config.yaml or environment variables
HIGH_DEST_THRESHOLD = settings.flags.high_dest_threshold
FAILURE_THRESHOLD = settings.flags.failure_threshold
USUAL_PORTS = set(settings.flags.usual_ports)


@app.get("/health", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


def _to_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Treat a naive stored timestamp as UTC so clients render the right instant.

    created_at is recorded with datetime.now(timezone.utc), but SQLite drops
    tzinfo on write, so it comes back naive. Serializing a naive datetime emits an
    offset-less ISO string that browsers parse as local time. Re-attach UTC so the
    API always reports an unambiguous instant.
    """
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _read_upload(upload: UploadFile, max_bytes: int, label: str) -> bytes:
    """Read an uploaded file, rejecting anything larger than max_bytes.

    Reads at most max_bytes + 1 so an oversized upload is caught without pulling
    the whole (potentially huge) file into memory first.
    """
    data = upload.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the maximum upload size of {max_bytes // (1024 * 1024)} MB",
        )
    return data


def _md_escape(value) -> str:
    """Neutralize attacker-influenced strings before writing them to markdown.

    Domains come from DNS labels observed in the uploaded trace and may contain
    characters (``|``, newlines, backticks) that would break out of a table cell
    or inject new structure -- including a forged "Verdict: PASS" line -- into the
    exported report. Escape the table delimiters and collapse control characters.
    """
    text = str(value)
    text = text.replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text)


def compute_aggregates(
    events: List[EventSchema],
    domain_candidates: Optional[dict] = None,
) -> dict:
    """Compute aggregated statistics from events."""
    domain_candidates = domain_candidates or {}
    if not events:
        return {
            "total_events": 0,
            "unique_ips": 0,
            "unique_ports": 0,
            "unique_destinations": 0,
            "failures": 0,
            "failure_rate": 0.0,
            "top_destinations": [],
        }

    total_events = len(events)
    unique_ips = len(set(e.dst_ip for e in events))
    unique_ports = len(set(e.dst_port for e in events))
    unique_destinations = len(set((e.dst_ip, e.dst_port) for e in events))
    failures = sum(1 for e in events if e.result != "ok")
    failure_rate = failures / total_events if total_events > 0 else 0.0

    dest_counter = Counter((e.dst_ip, e.dst_port) for e in events)

    # Most common protocol per destination in a single pass. The previous
    # implementation re-scanned every event for each unique destination, which is
    # O(unique_destinations * total_events); this is O(total_events). Counter
    # preserves first-seen insertion order for ties, matching the old behaviour.
    proto_counters: dict[tuple[str, int], Counter] = defaultdict(Counter)
    for e in events:
        proto_counters[(e.dst_ip, e.dst_port)][e.proto] += 1
    dest_protocols: dict[tuple[str, int], str] = {
        key: counter.most_common(1)[0][0] for key, counter in proto_counters.items()
    }

    top_destinations = []
    for (ip, port), count in dest_counter.most_common(50):
        candidates = list(domain_candidates.get(ip, []))
        if not candidates:
            event_domain_counts = Counter(
                (event.domain, event.domain_source)
                for event in events
                if event.dst_ip == ip and event.domain
            )
            candidates = [
                DomainCandidate(
                    domain=domain,
                    source=source,
                    count=candidate_count,
                )
                for (domain, source), candidate_count in event_domain_counts.items()
                if source
            ]

        primary = choose_primary_domain(candidates) if candidates else None
        top_destinations.append({
            "dst_ip": ip,
            "dst_port": port,
            "proto": dest_protocols.get((ip, port), "unknown"),
            "count": count,
            "domain": primary.domain if primary else None,
            "domain_source": primary.source if primary else None,
            "domains": [
                {
                    "domain": candidate.domain,
                    "source": candidate.source,
                    "count": candidate.count,
                }
                for candidate in sorted(
                    candidates,
                    key=lambda candidate: (
                        0 if candidate.source == "passive_dns" else 1,
                        -candidate.count,
                        candidate.domain,
                    ),
                )
            ],
        })

    return {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "unique_ports": unique_ports,
        "unique_destinations": unique_destinations,
        "failures": failures,
        "failure_rate": failure_rate,
        "top_destinations": top_destinations,
    }


def calculate_flags(events: List[EventSchema], summary: dict) -> List[dict]:
    """Calculate flags based on events and summary statistics.
    
    Uses configurable thresholds from config (environment/YAML).
    """
    flags = []

    # Flag 1: High unique destinations
    if summary.get("unique_destinations", 0) > HIGH_DEST_THRESHOLD:
        flags.append({
            "name": "High unique destinations",
            "description": f"Found {summary['unique_destinations']} unique destination IP:port pairs (threshold: {HIGH_DEST_THRESHOLD})",
            "severity": "medium",
        })

    # Flag 2: High failure rate
    if summary.get("failure_rate", 0.0) > FAILURE_THRESHOLD:
        flags.append({
            "name": "Elevated failure rate",
            "description": f"Failure rate is {summary['failure_rate']:.1%} (threshold: {FAILURE_THRESHOLD:.1%})",
            "severity": "medium",
        })

    # Flag 3: Unusual ports
    unusual_ports = set(e.dst_port for e in events if e.dst_port not in USUAL_PORTS)
    if unusual_ports:
        flags.append({
            "name": "Unusual ports",
            "description": f"Found connections to unusual ports: {sorted(unusual_ports)}",
            "severity": "medium",
        })

    return flags


def _destination_label(dest: dict) -> str:
    """Human label for an unexpected destination: domain if known, else ip:port."""
    if dest.get("domain"):
        return dest["domain"]
    return f"{dest['dst_ip']}:{dest['dst_port']}"


def policy_verdict_flag(policy: Optional[dict]) -> Optional[dict]:
    """Turn a failing policy verdict into a high-severity flag, or None.

    Surfacing the verdict as a flag means it renders in the existing UI panel and
    markdown export with no extra plumbing, and marks a failed egress policy as
    the most serious finding in the report.
    """
    if not policy or policy.get("verdict") != "fail":
        return None

    unexpected = policy.get("unexpected", [])
    count = policy.get("unexpected_count", len(unexpected))
    labels = [_destination_label(dest) for dest in unexpected[:5]]
    listed = ", ".join(labels)
    remaining = count - len(labels)
    if remaining > 0:
        listed += f", and {remaining} more"

    return {
        "name": "Unexpected destinations",
        "description": f"{count} destination(s) not on the allowlist: {listed}",
        "severity": "high",
    }


@app.post("/api/reports/upload", response_model=ReportUploadResponse, tags=["reports"])
def upload_report(
    file: UploadFile = File(...),
    metadata_file: Optional[UploadFile] = File(None),
    strace_file: Optional[UploadFile] = File(None),
    policy_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    """Upload and process a JSONL file to create a report.

    Defined as a sync endpoint so FastAPI runs it in a threadpool: JSONL parsing,
    aggregation, and the blocking reverse-DNS lookups in enrichment would
    otherwise stall the event loop for the whole process (up to
    reverse_dns_max_ips * timeout seconds per upload). Uploads are read via the
    synchronous .file handle for the same reason.
    """
    max_bytes = settings.uploads.max_upload_mb * 1024 * 1024

    # Read and parse JSONL file
    events = []
    try:
        content = _read_upload(file, max_bytes, "report file")
        lines = content.decode("utf-8").strip().split("\n")
        
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            
            try:
                event_data = json.loads(line)
                event = EventSchema(**event_data)
                events.append(event)
            except (json.JSONDecodeError, ValueError) as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid JSON on line {line_num}: {str(e)}"
                )
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")
    except HTTPException:
        # Re-raise the specific per-line error (e.g. "Invalid JSON on line N")
        # untouched; otherwise the broad handler below re-wraps it into a
        # confusing "Error reading file: 400: ..." message.
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")

    run_metadata = {}
    if metadata_file is not None:
        try:
            metadata_content = _read_upload(metadata_file, max_bytes, "run.json")
            if metadata_content:
                metadata_data = json.loads(metadata_content.decode("utf-8"))
                if not isinstance(metadata_data, dict):
                    raise ValueError("run metadata must be a JSON object")
                run_metadata = metadata_data
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="run.json must be UTF-8 encoded")
        except (json.JSONDecodeError, ValueError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid run.json: {str(e)}")

    strace_text = ""
    if strace_file is not None:
        try:
            strace_content = _read_upload(strace_file, max_bytes, "egress.strace")
            strace_text = strace_content.decode("utf-8", errors="ignore")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading egress.strace: {str(e)}")

    # Parse the optional allowlist before doing enrichment work so a malformed
    # policy fails fast with a clear 400.
    policy = None
    if policy_file is not None:
        try:
            policy_content = _read_upload(policy_file, max_bytes, "policy file")
            policy_data = json.loads(policy_content.decode("utf-8"))
            policy = load_policy(policy_data)
        except HTTPException:
            raise
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="policy file must be UTF-8 encoded")
        except RecursionError:
            raise HTTPException(status_code=400, detail="policy JSON is nested too deeply")
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid policy JSON: {str(e)}")
        except PolicyError as e:
            raise HTTPException(status_code=400, detail=f"Invalid policy: {str(e)}")

    if settings.enrichment.enabled:
        enrichment = enrich_events(
            events,
            strace_text,
            reverse_dns_enabled=settings.enrichment.reverse_dns_enabled,
            reverse_dns_timeout_seconds=settings.enrichment.reverse_dns_timeout_seconds,
            reverse_dns_max_ips=settings.enrichment.reverse_dns_max_ips,
        )
    else:
        enrichment = None

    # Compute aggregates
    summary = compute_aggregates(
        events,
        enrichment.domain_candidates if enrichment else {},
    )
    summary["enrichment"] = enrichment.summary() if enrichment else empty_enrichment_summary()

    # Judge destinations against the optional allowlist over ALL destinations,
    # using the same domain attribution the summary displays.
    if policy is not None:
        summary["policy"] = evaluate_policy(
            policy,
            events,
            enrichment.domain_candidates if enrichment else {},
        )

    # Store all parsed events so detail views and exports stay consistent with the summary.
    top_events = events

    # Calculate flags. A failing egress policy is the most serious finding, so it
    # goes first (flags render in list order).
    flags = calculate_flags(events, summary)
    policy_flag = policy_verdict_flag(summary.get("policy"))
    if policy_flag:
        flags.insert(0, policy_flag)

    # Create report
    report_id = str(uuid.uuid4())
    report = Report(
        id=report_id,
        run_metadata=run_metadata,
        summary=summary,
        top_events=[event.model_dump() for event in top_events],
        flags=flags,
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return ReportUploadResponse(report_id=report_id)


@app.get("/api/reports/{report_id}", response_model=ReportResponse, tags=["reports"])
def get_report(report_id: str, db: Session = Depends(get_db)):
    """Get a report by ID."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Convert stored event JSON to EventSchema objects
    top_events = [EventSchema(**event) for event in report.top_events]
    
    # Return flags that were computed during upload from ALL events.
    # Flags are calculated once on upload and stored with the report.
    # This ensures flags are consistent and accurate regardless of how many times the report is retrieved.
    # (Previously, flags were recalculated from top_events only, which could give incorrect results for large datasets)
    flags = report.flags

    return ReportResponse(
        id=report.id,
        created_at=_to_utc(report.created_at),
        metadata=report.run_metadata,  # Map run_metadata to metadata for API
        summary=report.summary,
        flags=flags,
        top_events=top_events,
    )


@app.get("/api/reports/{report_id}/events", tags=["reports"])
def get_report_events(
    report_id: str,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """Get events for a report with optional pagination."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Convert stored event JSON to EventSchema objects
    events = [EventSchema(**event) for event in report.top_events]

    # Apply limit if provided
    if limit is not None:
        events = events[:limit]

    return {
        "report_id": report_id,
        "total": len(report.top_events),
        "returned": len(events),
        "events": [event.model_dump() for event in events],
    }


@app.get("/api/reports/{report_id}/export.md", tags=["reports"])
def export_report_markdown(report_id: str, db: Session = Depends(get_db)):
    """Export a report as markdown."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Convert stored event JSON to EventSchema objects
    top_events = [EventSchema(**event) for event in report.top_events]

    # Generate markdown
    md_lines = [
        "# EgressLens Report",
        "",
        f"**Report ID:** `{report.id}`",
        f"**Created:** {_to_utc(report.created_at).isoformat()}",
        "",
        "## Summary",
        "",
    ]

    # Summary KPIs
    summary = report.summary
    md_lines.extend([
        f"- **Total Events:** {summary.get('total_events', 0)}",
        f"- **Unique IPs:** {summary.get('unique_ips', 0)}",
        f"- **Unique Ports:** {summary.get('unique_ports', 0)}",
        f"- **Unique Destinations:** {summary.get('unique_destinations', 0)}",
        f"- **Failures:** {summary.get('failures', 0)}",
        f"- **Failure Rate:** {summary.get('failure_rate', 0.0):.1%}",
        "",
    ])

    policy = summary.get("policy")
    if policy and policy.get("enabled"):
        verdict = "PASS" if policy.get("verdict") == "pass" else "FAIL"
        md_lines.extend([
            "## Egress Policy",
            "",
            f"- **Verdict:** {verdict}",
            f"- **Allow rules:** {policy.get('allow_rules', 0)}",
            f"- **Expected destinations:** {policy.get('expected_count', 0)}",
            f"- **Unexpected destinations:** {policy.get('unexpected_count', 0)}",
            "",
        ])
        if policy.get("has_domain_rules"):
            md_lines.extend([
                "> Domain rules are advisory: the matched domain is attributed from "
                "the traced process's own DNS traffic and could be forged by an "
                "evading subject. IP/CIDR rules are the hard gate.",
                "",
            ])
        unexpected = policy.get("unexpected", [])
        if unexpected:
            md_lines.extend([
                "| Domain | IP | Port | Protocol | Count |",
                "|--------|----|----|----------|-------|",
            ])
            for dest in unexpected:
                domain = _md_escape(dest.get("domain") or "-")
                ip = _md_escape(dest["dst_ip"])
                proto = _md_escape((dest.get("proto") or "-").upper())
                md_lines.append(
                    f"| {domain} | {ip} | {dest['dst_port']} | {proto} | {dest['count']} |"
                )
            shown = len(unexpected)
            total = policy.get("unexpected_count", shown)
            if total > shown:
                md_lines.append(f"_… and {total - shown} more not shown._")
            md_lines.append("")

    enrichment_summary = summary.get("enrichment") or {}
    if enrichment_summary:
        md_lines.extend([
            "## Enrichment",
            "",
            f"- **Passive DNS Matches:** {enrichment_summary.get('passive_matches', 0)}",
            f"- **Reverse DNS Matches:** {enrichment_summary.get('reverse_matches', 0)}",
            f"- **Unresolved IPs:** {enrichment_summary.get('unresolved_ips', 0)}",
            f"- **Skipped Reverse Lookups:** {enrichment_summary.get('skipped_reverse_lookups', 0)}",
            f"- **Lookup Errors:** {enrichment_summary.get('lookup_errors', 0)}",
            "",
        ])

    metadata = report.run_metadata or {}
    if metadata:
        command = metadata.get("command")
        command_text = " ".join(command) if isinstance(command, list) else str(command or "-")
        md_lines.extend([
            "## Run Details",
            "",
            f"- **Run ID:** `{metadata.get('run_id', '-')}`",
            f"- **Command:** `{command_text}`",
            f"- **Exit Code:** {metadata.get('exit_code', '-')}",
            f"- **Mode:** {metadata.get('mode', '-')}",
            f"- **Image:** `{metadata.get('image', '-')}`",
            f"- **Started:** {metadata.get('start_time', '-')}",
            f"- **Finished:** {metadata.get('end_time', '-')}",
            f"- **Working Directory:** `{metadata.get('cwd', '-')}`",
            "",
        ])

    # Flags
    if report.flags:
        md_lines.extend([
            "## Flags",
            "",
        ])
        for flag in report.flags:
            severity = flag.get("severity", "unknown")
            md_lines.extend([
                f"### {_md_escape(flag.get('name', 'Unknown'))} ({severity})",
                "",
                _md_escape(flag.get("description", "No description")),
                "",
            ])
    else:
        md_lines.extend([
            "## Flags",
            "",
            "No flags raised.",
            "",
        ])

    # Top Destinations
    top_destinations = summary.get("top_destinations", [])
    if top_destinations:
        md_lines.extend([
            "## Top Destinations",
            "",
            "| IP | Port | Protocol | Count | Domain | Source |",
            "|----|------|----------|-------|--------|--------|",
        ])
        for dest in top_destinations[:20]:  # Show top 20 in export
            domain = _md_escape(dest.get("domain") or "-")
            source = _md_escape(dest.get("domain_source") or "-")
            proto = _md_escape((dest.get("proto") or "-").upper())
            ip = _md_escape(dest["dst_ip"])
            md_lines.append(
                f"| {ip} | {dest['dst_port']} | {proto} | {dest['count']} | {domain} | {source} |"
            )
        md_lines.append("")

    # Top Events
    if top_events:
        md_lines.extend([
            "## Top Events",
            "",
            "| Timestamp | PID | IP | Port | Result |",
            "|-----------|-----|----|----|--------|",
        ])
        for event in top_events[:50]:  # Show top 50 events
            md_lines.append(
                f"| {event.ts} | {event.pid} | {_md_escape(event.dst_ip)} | {event.dst_port} | {_md_escape(event.result)} |"
            )
        md_lines.append("")

    markdown_content = "\n".join(md_lines)
    return Response(content=markdown_content, media_type="text/markdown")
