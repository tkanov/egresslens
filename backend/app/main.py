"""FastAPI application for EgressLens backend."""
import uuid
import json
from collections import Counter
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import init_db, get_db
from app.models import Report
from app.schemas import EventSchema, ReportUploadResponse, ReportResponse

app = FastAPI(
    title="EgressLens API",
    description="API for uploading and analyzing network egress monitoring data",
    version="1.0.0",
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

# Constants for flags calculation
HIGH_DEST_THRESHOLD = 50
FAILURE_THRESHOLD = 0.10
USUAL_PORTS = {80, 443, 53, 22}


@app.on_event("startup")
def startup_event():
    """Initialize database on startup."""
    init_db()


@app.get("/health", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


def compute_aggregates(events: List[EventSchema]) -> dict:
    """Compute aggregated statistics from events."""
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

    # Count destinations
    dest_counter = Counter((e.dst_ip, e.dst_port) for e in events)
    
    # Build protocol mapping for each destination (most common protocol)
    dest_protocols: dict[tuple[str, int], str] = {}
    for e in events:
        key = (e.dst_ip, e.dst_port)
        if key not in dest_protocols:
            # Find most common protocol for this destination
            protocols = [ev.proto for ev in events if ev.dst_ip == e.dst_ip and ev.dst_port == e.dst_port]
            dest_protocols[key] = Counter(protocols).most_common(1)[0][0]
    
    top_destinations = [
        {
            "dst_ip": ip,
            "dst_port": port,
            "proto": dest_protocols.get((ip, port), "unknown"),
            "count": count,
            "domain": next(
                (e.resolved_domain for e in events if e.dst_ip == ip and e.dst_port == port and e.resolved_domain),
                None
            ),
        }
        for (ip, port), count in dest_counter.most_common(50)
    ]

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
    """Calculate flags based on events and summary statistics."""
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


@app.post("/api/reports/upload", response_model=ReportUploadResponse, tags=["reports"])
async def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload and process a JSONL file to create a report."""
    # Read and parse JSONL file
    events = []
    try:
        content = await file.read()
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
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")

    # Compute aggregates
    summary = compute_aggregates(events)
    
    # Get top events (first 100)
    top_events = events[:100]
    
    # Calculate flags
    flags = calculate_flags(events, summary)

    # Create report
    report_id = str(uuid.uuid4())
    report = Report(
        id=report_id,
        run_metadata={},  # Could be enhanced to accept run.json separately
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

    # Convert top_events JSON to EventSchema objects
    top_events = [EventSchema(**event) for event in report.top_events]
    
    # Recalculate flags from stored events to ensure they use the latest logic
    # We need all events, not just top_events, so we'll use the stored events
    # For now, we'll recalculate from top_events (which may be a subset)
    # In a production system, you'd want to store all events or recalculate from the original file
    all_events = [EventSchema(**event) for event in report.top_events]
    flags = calculate_flags(all_events, report.summary)

    return ReportResponse(
        id=report.id,
        created_at=report.created_at,
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

    # Convert top_events JSON to EventSchema objects
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

    # Convert top_events JSON to EventSchema objects
    top_events = [EventSchema(**event) for event in report.top_events]

    # Generate markdown
    md_lines = [
        "# EgressLens Report",
        "",
        f"**Report ID:** `{report.id}`",
        f"**Created:** {report.created_at.isoformat()}",
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

    # Flags
    if report.flags:
        md_lines.extend([
            "## Flags",
            "",
        ])
        for flag in report.flags:
            severity = flag.get("severity", "unknown")
            md_lines.extend([
                f"### {flag.get('name', 'Unknown')} ({severity})",
                "",
                f"{flag.get('description', 'No description')}",
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
            "| IP | Port | Protocol | Count | Domain |",
            "|----|------|----------|-------|--------|",
        ])
        for dest in top_destinations[:20]:  # Show top 20 in export
            domain = dest.get("domain") or "-"
            proto = dest.get("proto", "-")
            md_lines.append(
                f"| {dest['dst_ip']} | {dest['dst_port']} | {proto.upper()} | {dest['count']} | {domain} |"
            )
        md_lines.append("")

    # Top Events
    if top_events:
        md_lines.extend([
            "## Top Events",
            "",
            "| Timestamp | PID | IP | Port | Result | Domain |",
            "|-----------|-----|----|----|--------|--------|",
        ])
        for event in top_events[:50]:  # Show top 50 events
            domain = event.resolved_domain or "-"
            md_lines.append(
                f"| {event.ts} | {event.pid} | {event.dst_ip} | {event.dst_port} | {event.result} | {domain} |"
            )
        md_lines.append("")

    markdown_content = "\n".join(md_lines)
    return Response(content=markdown_content, media_type="text/markdown")
