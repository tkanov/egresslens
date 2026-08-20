#!/usr/bin/env python3
"""Tests for `egresslens check`: verdicts, exit codes, and what a PASS rests on.

No Docker and no network. The reverse-DNS tests inject a resolver, which is why
`check_command` takes one.

Assertions on stderr go through `check_command` directly rather than through
CliRunner: click 8.1 (what the 3.9 leg resolves) merges stderr into
`result.output` and raises on `result.stderr`, while click 8.2+ separates them,
so only the direct call reads the same on every leg of the matrix.
"""

import json
from pathlib import Path

from click.testing import CliRunner

from egresslens import main as cli_main
from egresslens.check_command import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_INCONCLUSIVE,
    EXIT_PASS,
    check_command,
)
from egresslens.main import cli


# Any field given this value is left out of the record entirely, which is how the
# tests below say "absent" without a second helper.
DROP = "__DROP__"


def connect(ip="1.2.3.4", port: int = 443, proto: str = "tcp", **extra) -> dict:
    """One captured event, in the shape the CLI writes."""
    record = {
        "ts": 1.0,
        "pid": 7,
        "event": "connect",
        "family": "inet",
        "proto": proto,
        "dst_ip": ip,
        "dst_port": port,
        "result": "ok",
    }
    record.update(extra)
    return {key: value for key, value in record.items() if value != DROP}


def write_events(directory: Path, records: list) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "egress.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def write_policy(directory: Path, data) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def invoke(directory: Path, policy: Path, *args) -> object:
    return CliRunner().invoke(
        cli, ["check", str(directory), "--policy", str(policy), *args]
    )


# --- DNS answer fixtures, so a domain rule can be exercised end to end ---------
# Duplicated from backend/test_enrichment.py: the engine moved to this package
# but those byte builders are shared with the backend's upload tests, so they
# cannot simply follow it.

def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"


def dns_response(question: str, answers: list) -> bytes:
    question_bytes = dns_name(question) + b"\x00\x01\x00\x01"
    answer_bytes = b""
    for name, ip in answers:
        answer_name = b"\xc0\x0c" if name == question else dns_name(name)
        answer_bytes += (
            answer_name
            + b"\x00\x01\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + bytes(int(part) for part in ip.split("."))
        )
    return (
        b"\x12\x34\x81\x80"
        + b"\x00\x01"
        + len(answers).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + question_bytes
        + answer_bytes
    )


def strace_escape(payload: bytes) -> str:
    escaped = []
    for byte in payload:
        if byte == 92:
            escaped.append("\\\\")
        elif byte == 34:
            escaped.append('\\"')
        elif 32 <= byte <= 126:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\{byte:03o}")
    return "".join(escaped)


def write_strace(directory: Path, question: str, answers: list) -> Path:
    payload = dns_response(question, answers)
    line = (
        '123 1707150823.500 recvfrom(4, "'
        + strace_escape(payload)
        + '", 512, 0, {sa_family=AF_INET, sin_port=htons(53), '
        + 'sin_addr=inet_addr("8.8.8.8")}, [28 => 16]) = '
        + str(len(payload))
    )
    path = directory / "egress.strace"
    path.write_text(line + "\n", encoding="utf-8")
    return path


# --- Verdicts and exit codes ---------------------------------------------------

def test_ip_rule_covers_everything_is_a_pass(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("140.82.112.3"), connect("140.82.112.9", 80)])
    policy = write_policy(tmp_path, {"allow": ["140.82.112.0/20"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_PASS
    assert "Egress policy: PASS" in result.output
    assert "Expected via ip/CIDR rule: 2" in result.output


def test_one_unlisted_destination_fails_and_is_named(tmp_path):
    out = tmp_path / "capture"
    write_events(
        out,
        [connect("140.82.112.3"), connect("8.8.8.8", 53, "udp"), connect("8.8.8.8", 53, "udp")],
    )
    policy = write_policy(tmp_path, {"allow": ["140.82.112.0/20"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_FAIL
    assert "Egress policy: FAIL" in result.output
    row = [line for line in result.output.splitlines() if "8.8.8.8:53" in line]
    assert len(row) == 1, result.output
    assert "udp" in row[0]
    assert "2" in row[0]  # the observed count


def test_long_unexpected_list_is_elided_with_an_exact_remainder(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect(f"203.0.113.{i}") for i in range(25)])
    policy = write_policy(tmp_path, {"allow": ["10.0.0.0/8"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_FAIL
    rows = [line for line in result.output.splitlines() if "203.0.113." in line]
    assert len(rows) == 20
    assert "... and 5 more not shown." in result.output
    assert "Destinations evaluated: 25 (0 expected, 25 unexpected)" in result.output


def test_empty_events_file_is_inconclusive_not_a_pass(tmp_path):
    out = tmp_path / "capture"
    out.mkdir()
    (out / "egress.jsonl").write_text("", encoding="utf-8")
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_INCONCLUSIVE
    assert "Egress policy: INCONCLUSIVE" in result.output
    assert "not a pass" in result.output


def test_blank_lines_only_is_inconclusive(tmp_path):
    out = tmp_path / "capture"
    out.mkdir()
    (out / "egress.jsonl").write_text("\n  \n\n", encoding="utf-8")
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_INCONCLUSIVE
    assert "not a pass" in result.output


# --- Error paths: every one is 2, never 1 -------------------------------------
# 1 is FAIL. An input problem reported as 1 would read as a policy violation,
# which is the single most damaging way this command could be wrong.

def test_unparseable_policy_is_an_error_not_a_fail(tmp_path, capsys):
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    policy = tmp_path / "policy.json"
    policy.write_text("{not json", encoding="utf-8")

    assert check_command(directory=out, policy_path=policy) == EXIT_ERROR
    assert str(policy) in capsys.readouterr().err
    assert invoke(out, policy).exit_code == EXIT_ERROR


def test_empty_allow_list_is_an_error(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    assert invoke(out, write_policy(tmp_path, {"allow": []})).exit_code == EXIT_ERROR


def test_deny_only_policy_is_an_error(tmp_path):
    """The documented `deny`-is-ignored gotcha is a hard error here, not a pass."""
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    policy = write_policy(tmp_path, {"deny": ["evil.example"]})
    assert invoke(out, policy).exit_code == EXIT_ERROR


def test_unknown_key_in_a_rule_is_an_error(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    policy = write_policy(tmp_path, {"allow": [{"domian": "example.com"}]})
    assert invoke(out, policy).exit_code == EXIT_ERROR


def test_events_line_that_is_not_json_names_the_line(tmp_path, capsys):
    out = tmp_path / "capture"
    out.mkdir()
    (out / "egress.jsonl").write_text(
        json.dumps(connect("1.2.3.4")) + "\nnot json\n", encoding="utf-8"
    )
    policy = write_policy(tmp_path, {"allow": ["1.2.3.4"]})

    assert check_command(directory=out, policy_path=policy) == EXIT_ERROR
    assert "egress.jsonl:2" in capsys.readouterr().err


def test_unreadable_event_fields_are_errors(tmp_path):
    """Only values with no reading as a destination at all. See the test below."""
    policy = write_policy(tmp_path, {"allow": ["1.2.3.4"]})
    for index, record in enumerate(
        [
            connect("1.2.3.4", port=443.5),         # not a whole number
            connect("1.2.3.4", port="https"),       # not a number
            connect("1.2.3.4", port=None),
            connect("1.2.3.4", port="__DROP__"),    # no dst_port at all
            connect("__DROP__"),                    # no dst_ip at all
            connect(5),                             # dst_ip not a string
            connect("1.2.3.4", domain=17),          # would crash domain_matches
        ]
    ):
        out = tmp_path / f"capture{index}"
        write_events(out, [record])
        assert invoke(out, policy).exit_code == EXIT_ERROR, record


def test_every_value_the_upload_path_accepts_still_yields_a_verdict(tmp_path):
    """Measured against EventSchema in pydantic's lax mode, field by field.

    The upload endpoint grades all of these, so refusing them here would break
    the documented invariant in the one direction that hides a violation: an
    exit-2 error naming a field instead of a verdict naming a destination.
    """
    policy = write_policy(tmp_path, {"allow": ["1.2.3.4"]})
    accepted = [
        connect("1.2.3.4", port="443"),                  # numeric string
        connect("1.2.3.4", port=443.0),                  # integral float
        connect("1.2.3.4", port=0),                      # address-selection probe
        connect("1.2.3.4", port=65536),                  # out of range, still read
        connect("1.2.3.4", port=-1),
        connect("1.2.3.4", port=True),                   # pydantic reads bool as int
        connect("1.2.3.4", result="error"),              # a refused connect still counts
        connect("1.2.3.4", proto="__DROP__"),            # looser than EventSchema
        connect("1.2.3.4", ts="__DROP__", pid="__DROP__", result="__DROP__"),
    ]
    for index, record in enumerate(accepted):
        out = tmp_path / f"capture{index}"
        write_events(out, [record])
        result = invoke(out, policy)
        assert result.exit_code == EXIT_PASS, (record, result.output)

    # The empty destination address is accepted too, and fails closed: no ip rule
    # can match it, so it is reported unexpected rather than erroring the file out.
    out = tmp_path / "empty-ip"
    write_events(out, [connect("")])
    assert invoke(out, policy).exit_code == EXIT_FAIL


def test_port_zero_probes_do_not_convert_a_fail_into_an_error(tmp_path):
    """Regression: a 1..65535 floor on observed ports was a FAIL-to-ERROR primitive.

    The four port-0 lines are verbatim from a real `run-app` capture of an app
    that only called gethostbyname()/getaddrinfo(): glibc's RFC 3484 address
    sorting connect()s a UDP socket to each candidate answer with
    sin_port=htons(0). Today's parser drops those as silent probes, so this is
    the events file an older CLI, another tool, or a genuine connect(ip, 0)
    produces -- and the loader has to keep grading it, because the alternative is
    that one connect() to port 0 buries every violation in the file.
    """
    out = tmp_path / "capture"
    write_events(
        out,
        [
            connect("192.168.65.7", 53, "udp"),
            connect("104.20.23.154", 0, "udp"),
            connect("172.66.147.243", 0, "udp"),
            connect("104.20.23.154", 443, "tcp"),  # the real violation
        ],
    )
    policy = write_policy(tmp_path, {"allow": [{"ip": "192.168.65.7", "port": 53}]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_FAIL
    assert "104.20.23.154:443" in result.output
    assert "104.20.23.154:0" in result.output


def test_missing_artifacts_name_the_expected_path(tmp_path, capsys):
    policy = write_policy(tmp_path, {"allow": ["1.2.3.4"]})

    missing_dir = tmp_path / "nope"
    assert check_command(directory=missing_dir, policy_path=policy) == EXIT_ERROR
    assert str(missing_dir / "egress.jsonl") in capsys.readouterr().err

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert check_command(directory=empty_dir, policy_path=policy) == EXIT_ERROR
    assert str(empty_dir / "egress.jsonl") in capsys.readouterr().err

    assert invoke(missing_dir, policy).exit_code == EXIT_ERROR


def test_a_json_format_error_prints_no_json_and_still_exits_2(tmp_path, capsys):
    """`--format json | jq` must see empty stdout and 2, never a JSON verdict."""
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    policy = tmp_path / "policy.json"
    policy.write_text("{not json", encoding="utf-8")

    code = check_command(directory=out, policy_path=policy, output_format="json")
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert captured.out == ""
    assert str(policy) in captured.err
    assert invoke(out, policy, "--format", "json").exit_code == EXIT_ERROR


def test_strace_is_required_only_when_it_was_asked_for(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("1.2.3.4")])
    policy = write_policy(tmp_path, {"allow": ["1.2.3.4"]})

    # A capture with no trace is ordinary: it just means no passive DNS.
    assert invoke(out, policy).exit_code == EXIT_PASS
    # Naming one that is not there is a mistake worth reporting.
    named = invoke(out, policy, "--strace", str(tmp_path / "absent.strace"))
    assert named.exit_code == EXIT_ERROR


def test_events_elsewhere_do_not_pick_up_another_captures_trace(tmp_path):
    """The default trace follows the events, not the (possibly defaulted) DIRECTORY.

    Otherwise `check --events other/egress.jsonl` run in a directory holding an
    unrelated egresslens-output/ would judge one capture's events against another
    capture's DNS answers, and a domain rule could pass on attribution that never
    belonged to it.
    """
    stale = tmp_path / "egresslens-output"
    write_events(stale, [connect("93.184.216.34")])
    write_strace(stale, "example.com", [("example.com", "93.184.216.34")])
    elsewhere = tmp_path / "other"
    events = write_events(elsewhere, [connect("93.184.216.34")])
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = CliRunner().invoke(
        cli,
        ["check", str(stale), "--events", str(events), "--policy", str(policy),
         "--format", "json"],
    )
    assert result.exit_code == EXIT_FAIL
    assert json.loads(result.output)["strace"]["present"] is False
    # Naming the trace explicitly is still the way to combine them.
    named = CliRunner().invoke(
        cli,
        ["check", str(stale), "--events", str(events), "--policy", str(policy),
         "--strace", str(stale / "egress.strace")],
    )
    assert named.exit_code == EXIT_PASS


# --- Domains and enrichment ---------------------------------------------------

def test_domain_rule_matches_a_name_from_the_trace(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("93.184.216.34")])
    write_strace(out, "example.com", [("example.com", "93.184.216.34")])
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = invoke(out, policy, "--format", "json")
    assert result.exit_code == EXIT_PASS
    payload = json.loads(result.output)
    assert payload["expected_via_domain_only"] == 1
    assert payload["expected_via_ip"] == 0
    assert payload["enrichment"]["passive_matches"] == 1
    assert payload["strace"]["present"] is True


def test_domain_rule_matches_attribution_carried_by_the_events(tmp_path):
    """An already-enriched egress.jsonl is judged on its own attribution."""
    out = tmp_path / "capture"
    write_events(
        out,
        [connect("93.184.216.34", domain="example.com", domain_source="passive_dns")],
    )
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = invoke(out, policy, "--format", "json")
    assert result.exit_code == EXIT_PASS
    payload = json.loads(result.output)
    assert payload["expected_via_domain_only"] == 1
    assert payload["strace"]["present"] is False


def test_domain_rules_with_no_attributed_domains_warn_about_the_blind_spot(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("93.184.216.34")])
    policy = write_policy(tmp_path, {"allow": ["example.com"]})

    result = invoke(out, policy)
    assert result.exit_code == EXIT_FAIL
    assert "not one destination carried an attributed domain" in " ".join(result.output.split())
    assert "egress.strace" in result.output
    assert "domain/domain_source" in result.output


def test_no_reverse_dns_by_default(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("93.184.216.34")])
    policy = write_policy(tmp_path, {"allow": ["93.184.216.34"]})

    def resolver(ip):
        raise AssertionError(f"reverse DNS must not run by default (looked up {ip})")

    assert check_command(directory=out, policy_path=policy, resolver=resolver) == EXIT_PASS


def test_reverse_dns_names_a_destination_and_says_the_gate_moved(tmp_path, capsys):
    out = tmp_path / "capture"
    write_events(out, [connect("93.184.216.34")])
    policy = write_policy(tmp_path, {"allow": ["named.example.com"]})

    code = check_command(
        directory=out,
        policy_path=policy,
        reverse_dns=True,
        output_format="json",
        resolver=lambda ip: ("named.example.com", [], [ip]),
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_PASS
    assert payload["enrichment"]["reverse_matches"] == 1
    assert payload["enrichment"]["reverse_dns_enabled"] is True
    assert payload["expected_via_domain_only"] == 1
    assert any("reverse DNS" in note for note in payload["notes"])


def test_ip_rule_wins_the_split_over_a_domain_rule(tmp_path):
    """A hard gate is credited as one; a domain+ip rule is still domain-only."""
    out = tmp_path / "capture"
    write_events(
        out,
        [
            connect("1.1.1.1", domain="a.example", domain_source="passive_dns"),
            connect("2.2.2.2", domain="b.example", domain_source="passive_dns"),
        ],
    )
    policy = write_policy(
        tmp_path,
        {"allow": ["1.1.1.1", "a.example", {"domain": "b.example", "ip": "2.2.2.2"}]},
    )

    result = invoke(out, policy, "--format", "json")
    assert result.exit_code == EXIT_PASS
    payload = json.loads(result.output)
    assert payload["expected_via_ip"] == 1
    assert payload["expected_via_domain_only"] == 1


# --- Output format -----------------------------------------------------------

def test_json_output_is_the_only_thing_on_stdout(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("140.82.112.3"), connect("8.8.8.8", 53, "udp")])
    policy = write_policy(tmp_path, {"allow": ["140.82.112.0/20", "*.example.com"]})

    result = invoke(out, policy, "--format", "json")
    payload = json.loads(result.output)  # nothing but JSON, or this raises
    assert payload["schema_version"] == 1
    assert payload["verdict"] == payload["policy"]["verdict"] == "fail"
    assert payload["exit_code"] == EXIT_FAIL
    assert payload["policy"]["unexpected_count"] == 1
    assert payload["policy"]["path"] == str(policy)
    assert payload["events"]["count"] == 2
    assert payload["expected_via_ip"] == 1
    assert payload["expected_via_domain_only"] == 0
    assert payload["enrichment"]["reverse_dns_enabled"] is False
    assert payload["notes"]


def test_json_output_still_exits_with_the_verdict(tmp_path):
    out = tmp_path / "capture"
    write_events(out, [connect("8.8.8.8", 53, "udp")])
    policy = write_policy(tmp_path, {"allow": ["10.0.0.0/8"]})

    result = invoke(out, policy, "--format", "json")
    assert result.exit_code == EXIT_FAIL
    assert json.loads(result.output)["verdict"] == "fail"


# --- Composition with the capture commands ------------------------------------

class RecordingCheck:
    """A check_command stand-in that returns a fixed verdict and records calls."""

    def __init__(self, verdict_code: int):
        self.verdict_code = verdict_code
        self.calls = []

    def __call__(self, **kwargs) -> int:
        self.calls.append(kwargs)
        return self.verdict_code


def test_a_failing_verdict_overrides_a_successful_command(tmp_path, monkeypatch):
    check = RecordingCheck(EXIT_FAIL)
    monkeypatch.setattr(cli_main, "watch_command", lambda **kwargs: 0)
    monkeypatch.setattr(cli_main, "check_command", check)
    write_events(tmp_path / "out", [connect("1.2.3.4")])

    result = CliRunner().invoke(
        cli,
        ["watch", "--out", str(tmp_path / "out"), "--policy", str(tmp_path / "p.json"),
         "--", "true"],
    )
    assert result.exit_code == EXIT_FAIL
    assert len(check.calls) == 1


def test_a_passing_verdict_preserves_the_command_exit_code(tmp_path, monkeypatch):
    check = RecordingCheck(EXIT_PASS)
    monkeypatch.setattr(cli_main, "watch_command", lambda **kwargs: 7)
    monkeypatch.setattr(cli_main, "check_command", check)
    write_events(tmp_path / "out", [connect("1.2.3.4")])

    result = CliRunner().invoke(
        cli,
        ["watch", "--out", str(tmp_path / "out"), "--policy", str(tmp_path / "p.json"),
         "--", "true"],
    )
    assert result.exit_code == 7
    assert len(check.calls) == 1


def test_an_inconclusive_verdict_wins_over_the_command_exit_code(tmp_path, monkeypatch):
    check = RecordingCheck(EXIT_INCONCLUSIVE)
    monkeypatch.setattr(cli_main, "run_app_command", lambda **kwargs: 7)
    monkeypatch.setattr(cli_main, "check_command", check)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    write_events(tmp_path / "out", [connect("1.2.3.4")])

    result = CliRunner().invoke(
        cli,
        ["run-app", str(app_dir), "--out", str(tmp_path / "out"),
         "--policy", str(tmp_path / "p.json")],
    )
    assert result.exit_code == EXIT_INCONCLUSIVE
    assert len(check.calls) == 1


def test_a_capture_that_wrote_no_report_keeps_its_own_status(tmp_path, monkeypatch):
    """`run-app`'s documented 90 has to survive --policy, and so does its 1.

    A failed dependency install writes no events file, so there is nothing to
    judge; gating anyway replaced 90 with a 2 that reads as "malformed
    allowlist", in exactly the configuration the README recommends for CI.
    """
    check = RecordingCheck(EXIT_FAIL)
    monkeypatch.setattr(cli_main, "check_command", check)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    for capture_code in (90, 1):
        monkeypatch.setattr(cli_main, "run_app_command", lambda **kwargs: capture_code)
        result = CliRunner().invoke(
            cli,
            ["run-app", str(app_dir), "--out", str(out), "--policy", str(tmp_path / "p.json")],
        )
        assert result.exit_code == capture_code
    assert check.calls == []


def test_a_failing_capture_that_did_write_a_report_is_still_judged(tmp_path, monkeypatch):
    """The status alone is ambiguous: an app may exit 90 itself, and that run has
    a report. Only the missing report excuses a capture from the gate."""
    check = RecordingCheck(EXIT_FAIL)
    monkeypatch.setattr(cli_main, "run_app_command", lambda **kwargs: 90)
    monkeypatch.setattr(cli_main, "check_command", check)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    out = tmp_path / "out"
    write_events(out, [connect("1.2.3.4")])

    result = CliRunner().invoke(
        cli,
        ["run-app", str(app_dir), "--out", str(out), "--policy", str(tmp_path / "p.json")],
    )
    assert result.exit_code == EXIT_FAIL
    assert len(check.calls) == 1


def test_a_successful_capture_with_no_report_is_not_excused(tmp_path, monkeypatch):
    """Exit 0 and no events file must reach the gate, and error there."""
    check = RecordingCheck(EXIT_ERROR)
    monkeypatch.setattr(cli_main, "watch_command", lambda **kwargs: 0)
    monkeypatch.setattr(cli_main, "check_command", check)

    result = CliRunner().invoke(
        cli,
        ["watch", "--out", str(tmp_path / "empty"), "--policy", str(tmp_path / "p.json"),
         "--", "true"],
    )
    assert result.exit_code == EXIT_ERROR
    assert len(check.calls) == 1


def test_without_policy_nothing_is_evaluated_and_the_exit_code_is_the_command_s(
    tmp_path, monkeypatch
):
    """The no-default-behaviour-change guard: no --policy, no verdict, no new code."""
    check = RecordingCheck(EXIT_FAIL)
    monkeypatch.setattr(cli_main, "watch_command", lambda **kwargs: 7)
    monkeypatch.setattr(cli_main, "run_app_command", lambda **kwargs: 7)
    monkeypatch.setattr(cli_main, "check_command", check)
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    watched = CliRunner().invoke(cli, ["watch", "--out", str(tmp_path / "out"), "--", "true"])
    ran = CliRunner().invoke(cli, ["run-app", str(app_dir), "--out", str(tmp_path / "out")])

    assert watched.exit_code == 7
    assert ran.exit_code == 7
    assert check.calls == []


def main():
    import subprocess
    raise SystemExit(subprocess.call(["pytest", "-v", __file__]))


if __name__ == "__main__":
    main()
