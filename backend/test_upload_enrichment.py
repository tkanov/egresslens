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


def test_invalid_jsonl_line_reports_clean_error():
    try:
        with make_client() as client:
            response = client.post(
                "/api/reports/upload",
                files={"file": ("egress.jsonl", "not json at all\n", "application/x-ndjson")},
            )
            assert response.status_code == 400, response.text
            detail = response.json()["detail"]
            # The specific per-line message must survive, not be re-wrapped by the
            # broad handler into "Error reading file: 400: ...".
            assert detail.startswith("Invalid JSON on line 1"), detail
    finally:
        main_app.app.dependency_overrides.clear()
    print("invalid JSONL line reports a clean per-line error")


def test_oversized_upload_is_rejected():
    original = main_app.settings.uploads.max_upload_mb
    main_app.settings.uploads.max_upload_mb = 1
    try:
        with make_client() as client:
            # ~1 MB + 1 KB of content, just over the 1 MB cap. Rejected on size
            # before any parsing, so the body need not be valid JSONL.
            oversized = "x" * (1024 * 1024 + 1024)
            response = client.post(
                "/api/reports/upload",
                files={"file": ("egress.jsonl", oversized, "application/x-ndjson")},
            )
            assert response.status_code == 413, response.text
    finally:
        main_app.settings.uploads.max_upload_mb = original
        main_app.app.dependency_overrides.clear()
    print("oversized upload is rejected with 413")


def _upload_with_policy(client, policy: str):
    """Upload an event for 93.184.216.34 (resolves to example.com) with a policy."""
    payload = dns_response("example.com", [("example.com", "93.184.216.34")])
    return client.post(
        "/api/reports/upload",
        files={
            "file": ("egress.jsonl", jsonl_event("93.184.216.34"), "application/x-ndjson"),
            "strace_file": ("egress.strace", strace_recv_line(payload), "text/plain"),
            "policy_file": ("policy.json", policy, "application/json"),
        },
    )


def test_policy_pass_records_verdict_without_flag():
    original_reverse = main_app.settings.enrichment.reverse_dns_enabled
    main_app.settings.enrichment.reverse_dns_enabled = False
    try:
        with make_client() as client:
            response = _upload_with_policy(client, '{"allow": ["example.com"]}')
            assert response.status_code == 200, response.text
            report = client.get(f"/api/reports/{response.json()['report_id']}").json()
            policy = report["summary"]["policy"]
            assert policy["verdict"] == "pass"
            assert policy["expected_count"] == 1
            assert policy["unexpected_count"] == 0
            assert not any(f["name"] == "Unexpected destinations" for f in report["flags"])
    finally:
        main_app.settings.enrichment.reverse_dns_enabled = original_reverse
        main_app.app.dependency_overrides.clear()
    print("policy pass records a verdict and raises no flag")


def test_policy_fail_raises_high_severity_flag():
    original_reverse = main_app.settings.enrichment.reverse_dns_enabled
    main_app.settings.enrichment.reverse_dns_enabled = False
    try:
        with make_client() as client:
            response = _upload_with_policy(client, '{"allow": ["pypi.org"]}')
            assert response.status_code == 200, response.text
            report = client.get(f"/api/reports/{response.json()['report_id']}").json()
            policy = report["summary"]["policy"]
            assert policy["verdict"] == "fail"
            assert policy["unexpected_count"] == 1
            assert policy["unexpected"][0]["domain"] == "example.com"
            flag = next(f for f in report["flags"] if f["name"] == "Unexpected destinations")
            assert flag["severity"] == "high"
            assert "example.com" in flag["description"]
    finally:
        main_app.settings.enrichment.reverse_dns_enabled = original_reverse
        main_app.app.dependency_overrides.clear()
    print("policy fail raises a high-severity flag")


def test_malformed_policy_is_rejected():
    try:
        with make_client() as client:
            response = client.post(
                "/api/reports/upload",
                files={
                    "file": ("egress.jsonl", jsonl_event("93.184.216.34"), "application/x-ndjson"),
                    "policy_file": ("policy.json", '{"allow": [{"port": 443}]}', "application/json"),
                },
            )
            assert response.status_code == 400, response.text
            assert "policy" in response.json()["detail"].lower()
    finally:
        main_app.app.dependency_overrides.clear()
    print("malformed policy is rejected with 400")


def main():
    test_jsonl_only_upload_still_works()
    test_upload_with_strace_enriches_events_and_top_destinations()
    test_report_created_at_is_utc_aware()
    test_invalid_jsonl_line_reports_clean_error()
    test_oversized_upload_is_rejected()
    test_policy_pass_records_verdict_without_flag()
    test_policy_fail_raises_high_severity_flag()
    test_malformed_policy_is_rejected()
    print("all upload enrichment tests passed")


if __name__ == "__main__":
    main()
