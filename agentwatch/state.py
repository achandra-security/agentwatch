"""Per-session state that detection rules consult.

The engine evaluates every rule against an event *before* applying that event
to the session state, so rules always see what was known prior to the event.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import events as ev
from .events import AgentEvent

SENSITIVE_LEVELS = frozenset({"confidential", "secret"})


@dataclass
class SessionState:
    session_id: str
    tenant_id: str | None = None
    principal_id: str | None = None
    root_agent_id: str | None = None
    identity_bindings: dict[str, str] = field(default_factory=dict)  # agent -> workload id
    agent_scopes: dict[str, frozenset[str]] = field(default_factory=dict)
    delegation_parent: dict[str, str] = field(default_factory=dict)  # child -> parent
    approvals: dict[str, AgentEvent] = field(default_factory=dict)  # tool_call_id -> event
    denials: dict[str, AgentEvent] = field(default_factory=dict)
    untrusted_ingests: list[AgentEvent] = field(default_factory=list)
    sensitive_reads: list[AgentEvent] = field(default_factory=list)
    tool_calls: list[AgentEvent] = field(default_factory=list)

    def delegation_chain(self, agent_id: str) -> list[str]:
        """Return the chain from the root agent down to ``agent_id``."""
        chain = [agent_id]
        seen = {agent_id}
        current = agent_id
        while current in self.delegation_parent:
            current = self.delegation_parent[current]
            if current in seen:  # defensive: malformed telemetry with a cycle
                break
            seen.add(current)
            chain.append(current)
        return list(reversed(chain))

    def delegation_depth(self, agent_id: str) -> int:
        return len(self.delegation_chain(agent_id)) - 1

    def apply(self, event: AgentEvent) -> None:
        kind = event.event_type
        if kind == "session.start":
            self.tenant_id = event.get(ev.TENANT)
            self.principal_id = event.get(ev.PRINCIPAL)
            self.root_agent_id = event.agent_id
            self.identity_bindings[event.agent_id] = event.get(ev.WORKLOAD_ID)
            self.agent_scopes[event.agent_id] = frozenset(event.get(ev.SCOPES, []))
        elif kind == "agent.delegate":
            child = event.get(ev.CHILD_AGENT)
            self.delegation_parent[child] = event.get(ev.PARENT_AGENT)
            self.agent_scopes[child] = frozenset(event.get(ev.SCOPES, []))
            if event.get(ev.CHILD_WORKLOAD):
                self.identity_bindings[child] = event.get(ev.CHILD_WORKLOAD)
        elif kind == "content.ingest":
            if event.get(ev.TRUST) == "untrusted":
                self.untrusted_ingests.append(event)
        elif kind == "approval.granted":
            self.approvals[event.get(ev.TOOL_CALL_ID)] = event
        elif kind == "approval.denied":
            self.denials[event.get(ev.TOOL_CALL_ID)] = event
        elif kind == "tool.call":
            self.tool_calls.append(event)
            if event.get(ev.SENSITIVITY) in SENSITIVE_LEVELS and event.get(ev.ACTION_CLASS) == "read":
                self.sensitive_reads.append(event)
