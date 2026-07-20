#!/usr/bin/env python3
"""Upload endpoint tests for backend enrichment."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_app
from app.models import Base
from test_enrichment import dns_response, strace_recv_line


def jsonl_event(ip: str, port: int = 443) -> str:
    return json.dumps({
        "ts": 1.0,
        "pid": 100,
        "event": "connect",
        "family": "inet",
        "proto": "tcp",
        "dst_ip": ip,
        "dst_port": port,
        "result": "ok",
    }) + "\n"


def make_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    main_app.app.dependency_overrides[main_app.get_db] = override_get_db
    return TestClient(main_app.app)


def test_jsonl_only_upload_still_works():
    original_reverse = main_app.settings.enrichment.reverse_dns_enabled
    main_app.settings.enrichment.reverse_dns_enabled = False
    try:
        with make_client() as client:
            response = client.post(
                "/api/reports/upload",
                files={"file": ("egress.jsonl", jsonl_event("93.184.216.34"), "application/x-ndjson")},
            )
            assert response.status_code == 200, response.text
            report_id = response.json()["report_id"]
            report = client.get(f"/api/reports/{report_id}").json()
            assert report["summary"]["total_events"] == 1
            assert report["summary"]["top_destinations"][0]["domain"] is None
            assert report["summary"]["enrichment"]["unresolved_ips"] == 1
    finally:
        main_app.settings.enrichment.reverse_dns_enabled = original_reverse
        main_app.app.dependency_overrides.clear()
    print("JSONL-only upload remains backward compatible")


def test_upload_with_strace_enriches_events_and_top_destinations():
    original_reverse = main_app.settings.enrichment.reverse_dns_enabled
    main_app.settings.enrichment.reverse_dns_enabled = False
    payload = dns_response("example.com", [("example.com", "93.184.216.34")])
    try:
        with make_client() as client:
            response = client.post(
                "/api/reports/upload",
                files={
                    "file": ("egress.jsonl", jsonl_event("93.184.216.34"), "application/x-ndjson"),
                    "strace_file": ("egress.strace", strace_recv_line(payload), "text/plain"),
                },
            )
            assert response.status_code == 200, response.text
            report_id = response.json()["report_id"]
            report = client.get(f"/api/reports/{report_id}").json()
            destination = report["summary"]["top_destinations"][0]
            assert destination["domain"] == "example.com"
            assert destination["domain_source"] == "passive_dns"
            assert destination["domains"] == [
                {"domain": "example.com", "source": "passive_dns", "count": 1}
            ]
            assert report["top_events"][0]["domain"] == "example.com"
            assert report["top_events"][0]["domain_source"] == "passive_dns"
            assert report["summary"]["enrichment"]["passive_matches"] == 1
    finally:
        main_app.settings.enrichment.reverse_dns_enabled = original_reverse
        main_app.app.dependency_overrides.clear()
    print("upload with strace enriches stored events and top destinations")


def test_report_created_at_is_utc_aware():
    original_reverse = main_app.settings.enrichment.reverse_dns_enabled
    main_app.settings.enrichment.reverse_dns_enabled = False
    try:
        with make_client() as client:
            response = client.post(
                "/api/reports/upload",
                files={"file": ("egress.jsonl", jsonl_event("93.184.216.34"), "application/x-ndjson")},
            )
            assert response.status_code == 200, response.text
            report_id = response.json()["report_id"]
            created_at = client.get(f"/api/reports/{report_id}").json()["created_at"]
            # Naive SQLite timestamps must be emitted with an explicit UTC marker
            # ("Z" or "+00:00"), otherwise browsers parse the offset-less string as
            # local time.
            assert created_at.endswith(("Z", "+00:00")), created_at
    finally:
        main_app.settings.enrichment.reverse_dns_enabled = original_reverse
        main_app.app.dependency_overrides.clear()
    print("report created_at is serialized as UTC-aware")


def main():
    test_jsonl_only_upload_still_works()
    test_upload_with_strace_enriches_events_and_top_destinations()
    test_report_created_at_is_utc_aware()
    print("all upload enrichment tests passed")


if __name__ == "__main__":
    main()
