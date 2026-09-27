import json
from pathlib import Path

import pytest

from agentwatch import DetectionEngine, EventValidationError, load_events, parse_events
from agentwatch.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

EXPECTED = {
    "benign_session.jsonl": [],
    "indirect_injection_exfil.jsonl": ["AW-003", "AW-004"],
    "cross_tenant_retrieval.jsonl": ["AW-001", "AW-001"],
    "unapproved_destructive_actions.jsonl": ["AW-002", "AW-002", "AW-002", "AW-005"],
    "delegation_abuse.jsonl": ["AW-006", "AW-007", "AW-008", "AW-008", "AW-009"],
}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_fixture_expected_findings(name, expected):
    findings = DetectionEngine().analyze(load_events(FIXTURES / name))
    assert sorted(f.rule_id for f in findings) == expected


def test_every_finding_is_explainable():
    for name in EXPECTED:
        events = load_events(FIXTURES / name)
        known = {e.event_id for e in events}
        for f in DetectionEngine().analyze(events):
            assert f.explanation and f.response and f.references
            assert f.evidence and set(f.evidence) <= known


def test_analysis_is_deterministic():
    events = load_events(FIXTURES / "delegation_abuse.jsonl")
    first = [f.to_dict() for f in DetectionEngine().analyze(events)]
    second = [f.to_dict() for f in DetectionEngine().analyze(list(reversed(events)))]
    assert first == second


@pytest.mark.parametrize(
    "record,message",
    [
        ({"event_id": "1", "session_id": "s", "event_type": "tool.call"}, "timestamp"),
        ({"event_id": "1", "timestamp": "2026-09-01T00:00:00Z", "session_id": "s", "event_type": "nope"}, "unknown"),
        (
            {"event_id": "1", "timestamp": "2026-09-01T00:00:00", "session_id": "s", "event_type": "content.ingest",
             "attributes": {"gen_ai.agent.id": "a", "agentwatch.provenance.trust": "untrusted"}},
            "timezone",
        ),
        (
            {"event_id": "1", "timestamp": "2026-09-01T00:00:00Z", "session_id": "s", "event_type": "tool.call",
             "attributes": {"gen_ai.agent.id": "a", "gen_ai.tool.name": "t", "gen_ai.tool.call.id": "c",
                            "agentwatch.tool.action_class": "explode"}},
            "action_class",
        ),
    ],
)
def test_schema_validation(record, message):
    with pytest.raises(EventValidationError, match=message):
        parse_events([record])


def test_cli_text_report(capsys):
    assert main(["analyze", str(FIXTURES / "indirect_injection_exfil.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "[CRITICAL] AW-004" in out and "[HIGH] AW-003" in out


def test_cli_ndjson_is_siem_ready(capsys):
    main(["analyze", str(FIXTURES / "cross_tenant_retrieval.jsonl"), "--format", "ndjson"])
    records = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert len(records) == 2
    for r in records:
        assert r["event.kind"] == "alert" and r["rule.id"] == "AW-001"
        assert r["@timestamp"].endswith("Z") and isinstance(r["event.severity"], int)


def test_cli_fail_on_and_min_severity(capsys):
    path = str(FIXTURES / "delegation_abuse.jsonl")
    assert main(["analyze", path, "--fail-on", "high", "--format", "json"]) == 2
    capsys.readouterr()
    assert main(["analyze", path, "--min-severity", "critical", "--fail-on", "high", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_allow_egress_suppresses_exfil_finding(capsys):
    path = str(FIXTURES / "indirect_injection_exfil.jsonl")
    main(["analyze", path, "--format", "json", "--allow-egress", "collector.attacker.example"])
    assert [f["rule_id"] for f in json.loads(capsys.readouterr().out)] == ["AW-003"]


def test_cli_reports_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json}\n")
    assert main(["analyze", str(bad)]) == 1
    assert "bad.jsonl:1" in capsys.readouterr().err


def test_cli_lists_rules(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert all(f"AW-{i:03d}" in out for i in range(1, 11))


def test_cli_hec_envelopes(capsys):
    main(["analyze", str(FIXTURES / "indirect_injection_exfil.jsonl"), "--format", "hec"])
    envelopes = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines()]
    assert {e["sourcetype"] for e in envelopes} == {"agentwatch:finding"}
    assert all(isinstance(e["time"], float) and e["event"]["event.kind"] == "alert" for e in envelopes)
