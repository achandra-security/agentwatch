from datetime import timedelta

import pytest

from agentwatch import DetectionEngine, EngineConfig, parse_events

SPIFFE = "spiffe://example.test/agents/a"


def ev(n, event_type, seconds=None, session="s1", **attrs):
    return {
        "event_id": f"e{n}",
        "timestamp": f"2026-09-01T14:{(seconds if seconds is not None else n * 5) // 60:02d}:"
        f"{(seconds if seconds is not None else n * 5) % 60:02d}Z",
        "session_id": session,
        "event_type": event_type,
        "attributes": attrs,
    }


def start(scopes=("x.read",), tenant="t1"):
    return ev(
        0,
        "session.start",
        **{
            "gen_ai.agent.id": "a",
            "agentwatch.workload.id": SPIFFE,
            "agentwatch.principal.id": "user:u",
            "agentwatch.tenant.id": tenant,
            "agentwatch.delegation.scopes": list(scopes),
        },
    )


def call(n, action="read", tool="t", call_id=None, agent="a", **extra):
    attrs = {
        "gen_ai.agent.id": agent,
        "gen_ai.tool.name": tool,
        "gen_ai.tool.call.id": call_id or f"c{n}",
        "agentwatch.tool.action_class": action,
    }
    attrs.update({f"agentwatch.{k}": v for k, v in extra.items()})
    return ev(n, "tool.call", **attrs)


def run(records, config=None):
    return DetectionEngine(config).analyze(parse_events(records))


def ids(findings):
    return sorted(f.rule_id for f in findings)


# AW-001 -------------------------------------------------------------------


def test_cross_tenant_read_is_high_and_write_is_critical():
    findings = run(
        [
            start(),
            call(1, "read", **{"resource.tenant": "t2"}),
            call(2, "write", **{"resource.tenant": "t2"}),
        ]
    )
    assert [(f.rule_id, f.severity) for f in findings] == [("AW-001", "high"), ("AW-001", "critical")]
    assert "t2" in findings[0].explanation and "t1" in findings[0].explanation


def test_same_tenant_access_is_clean():
    assert run([start(), call(1, **{"resource.tenant": "t1"})]) == []


# AW-002 -------------------------------------------------------------------


def approval(n, call_id, approver="user:u", approver_type="human", kind="approval.granted"):
    return ev(
        n,
        kind,
        **{
            "gen_ai.tool.call.id": call_id,
            "agentwatch.approval.approver_id": approver,
            "agentwatch.approval.approver_type": approver_type,
        },
    )


def test_irreversible_with_human_approval_is_clean():
    assert run([start(), approval(1, "c2"), call(2, "irreversible")]) == []


@pytest.mark.parametrize(
    "records,phrase",
    [
        ([call(2, "irreversible")], "no approval"),
        ([approval(1, "c2", "a", "agent"), call(2, "irreversible")], "agent principal"),
        ([approval(1, "c2", kind="approval.denied"), call(2, "irreversible")], "explicitly denied"),
        ([approval(1, "OTHER"), call(2, "irreversible")], "no approval"),
    ],
)
def test_irreversible_without_valid_approval(records, phrase):
    findings = run([start(), *records])
    assert ids(findings) == ["AW-002"]
    assert phrase in findings[0].explanation


def test_approval_from_session_agent_labelled_human_is_rejected():
    findings = run([start(), approval(1, "c2", approver="a"), call(2, "irreversible")])
    assert ids(findings) == ["AW-002"]


# AW-003 -------------------------------------------------------------------


def ingest(n, trust="untrusted"):
    return ev(
        n,
        "content.ingest",
        **{"gen_ai.agent.id": "a", "agentwatch.provenance.trust": trust, "agentwatch.provenance.source": "web page"},
    )


def test_untrusted_content_then_write_fires():
    findings = run([start(), ingest(1), call(2, "write")])
    assert ids(findings) == ["AW-003"]
    assert findings[0].evidence == ("e1", "e2")


def test_untrusted_content_then_read_is_clean():
    assert run([start(), ingest(1), call(2, "read")]) == []


def test_trusted_content_is_ignored():
    assert run([start(), ingest(1, trust="trusted"), call(2, "write")]) == []


def test_untrusted_window_expires():
    config = EngineConfig(untrusted_window=timedelta(seconds=30))
    records = [start(), ingest(1), call(2, "write")]
    records[2]["timestamp"] = "2026-09-01T14:10:00Z"
    assert run(records, config) == []


# AW-004 / AW-005 sequences -------------------------------------------------


def test_sensitive_read_then_unlisted_egress():
    findings = run(
        [
            start(),
            call(1, "read", **{"data.sensitivity": "secret"}),
            call(2, "egress", **{"egress.destination": "evil.example"}),
        ]
    )
    assert ids(findings) == ["AW-004"]
    assert findings[0].evidence == ("e1", "e2")


def test_egress_to_allowlisted_destination_is_clean():
    config = EngineConfig(egress_allowlist=frozenset({"api.partner.example"}))
    findings = run(
        [
            start(),
            call(1, "read", **{"data.sensitivity": "secret"}),
            call(2, "egress", **{"egress.destination": "api.partner.example"}),
        ],
        config,
    )
    assert findings == []


def test_egress_without_prior_sensitive_read_is_clean():
    assert run([start(), call(1, "read"), call(2, "egress", **{"egress.destination": "x.example"})]) == []


def test_sequence_order_matters():
    findings = run(
        [
            start(),
            call(1, "egress", **{"egress.destination": "x.example"}),
            call(2, "read", **{"data.sensitivity": "secret"}),
        ]
    )
    assert findings == []


def test_control_tampering_then_irreversible():
    findings = run(
        [
            start(),
            approval(1, "c3"),
            call(2, "write", **{"tool.category": "security_control"}),
            call(3, "irreversible"),
        ]
    )
    assert ids(findings) == ["AW-005"]


# Delegation and identity ----------------------------------------------------


def delegate(n, parent, child, scopes, workload=None):
    attrs = {
        "agentwatch.delegation.parent_agent_id": parent,
        "agentwatch.delegation.child_agent_id": child,
        "agentwatch.delegation.scopes": scopes,
    }
    if workload:
        attrs["agentwatch.delegation.child_workload_id"] = workload
    return ev(n, "agent.delegate", **attrs)


def test_delegation_scope_escalation():
    findings = run([start(scopes=["x.read"]), delegate(1, "a", "b", ["x.read", "x.write"])])
    assert ids(findings) == ["AW-006"]
    assert "x.write" in findings[0].explanation


def test_narrowing_delegation_is_clean():
    assert run([start(scopes=["x.read", "x.write"]), delegate(1, "a", "b", ["x.read"])]) == []


def test_delegation_depth_limit():
    records = [
        start(scopes=["x.read"]),
        delegate(1, "a", "b", ["x.read"]),
        delegate(2, "b", "c", ["x.read"]),
        delegate(3, "c", "d", ["x.read"]),
    ]
    findings = run(records, EngineConfig(max_delegation_depth=2))
    assert ids(findings) == ["AW-007"]
    assert "a -> b -> c -> d" in findings[0].explanation


def test_workload_mismatch_and_unbound_agent():
    findings = run(
        [
            start(),
            call(1, **{"workload.id": "spiffe://example.test/agents/other"}),
            call(2, agent="stranger"),
        ]
    )
    assert [(f.rule_id, f.severity) for f in findings] == [("AW-008", "high"), ("AW-008", "medium")]


def test_tool_outside_delegated_scope():
    findings = run([start(scopes=["x.read"]), call(1, **{"tool.required_scope": "x.admin"})])
    assert ids(findings) == ["AW-009"]


def test_delegation_chain_is_reported_on_findings():
    findings = run(
        [
            start(scopes=["x.read"]),
            delegate(1, "a", "b", ["x.read"], workload="spiffe://example.test/agents/b"),
            call(2, agent="b", **{"tool.required_scope": "x.write"}),
        ]
    )
    assert findings[0].delegation_chain == ("a", "b")


# AW-010 ------------------------------------------------------------------


def test_burst_fires_once_when_threshold_exceeded():
    config = EngineConfig(burst_threshold=5, burst_window=timedelta(seconds=60))
    records = [start()] + [call(i) for i in range(1, 9)]
    findings = run(records, config)
    assert ids(findings) == ["AW-010"]


def test_sessions_are_isolated():
    other = ev(1, "tool.call", session="s2", **{
        "gen_ai.agent.id": "a", "gen_ai.tool.name": "t", "gen_ai.tool.call.id": "c1",
        "agentwatch.tool.action_class": "read", "agentwatch.resource.tenant": "t2"})
    # s2 has no session.start, so no tenant is bound: AW-001 cannot fire, but the unbound agent is flagged.
    assert ids(run([start(), other])) == ["AW-008"]
