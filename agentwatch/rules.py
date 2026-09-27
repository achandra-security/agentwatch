"""Explainable detection rules.

Each rule is a small, deterministic class. A finding always carries:
the rule that fired, a human-readable explanation built from the observed
values, the IDs of the evidence events, and a recommended response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Sequence

from . import events as ev
from .events import AgentEvent
from .state import SENSITIVE_LEVELS, SessionState

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def _a(word: str) -> str:
    return f"an {word}" if str(word)[:1].lower() in "aeiou" else f"a {word}"


OWASP_LLM01 = "OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection"
OWASP_LLM02 = "OWASP Top 10 for LLM Applications 2025: LLM02 Sensitive Information Disclosure"
OWASP_LLM06 = "OWASP Top 10 for LLM Applications 2025: LLM06 Excessive Agency"
OWASP_LLM08 = "OWASP Top 10 for LLM Applications 2025: LLM08 Vector and Embedding Weaknesses"
OWASP_LLM10 = "OWASP Top 10 for LLM Applications 2025: LLM10 Unbounded Consumption"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    session_id: str
    agent_id: str | None
    timestamp: str
    explanation: str
    evidence: tuple[str, ...]
    response: str
    references: tuple[str, ...] = ()
    delegation_chain: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
            "delegation_chain": list(self.delegation_chain),
            "response": self.response,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class EngineConfig:
    egress_allowlist: frozenset[str] = frozenset()
    max_delegation_depth: int = 2
    untrusted_window: timedelta = timedelta(minutes=15)
    sequence_window: timedelta = timedelta(minutes=30)
    burst_threshold: int = 20
    burst_window: timedelta = timedelta(seconds=60)


class Rule:
    rule_id: str = ""
    title: str = ""
    severity: str = "medium"
    description: str = ""
    response: str = ""
    references: tuple[str, ...] = ()

    def __init__(self, config: EngineConfig):
        self.config = config

    def evaluate(self, event: AgentEvent, state: SessionState) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        event: AgentEvent,
        state: SessionState,
        explanation: str,
        evidence: Sequence[str],
        severity: str | None = None,
        agent_id: str | None = None,
    ) -> Finding:
        agent = agent_id or event.agent_id
        chain = tuple(state.delegation_chain(agent)) if agent else ()
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity or self.severity,
            session_id=event.session_id,
            agent_id=agent,
            timestamp=event.iso_timestamp,
            explanation=explanation,
            evidence=tuple(dict.fromkeys(evidence)),
            response=self.response,
            references=self.references,
            delegation_chain=chain,
        )


class CrossTenantAccess(Rule):
    rule_id = "AW-001"
    title = "Cross-tenant resource access"
    severity = "high"
    description = "A tool call touched a resource owned by a tenant other than the session tenant."
    response = "Block the call path, confirm retrieval-time tenant filters, review data returned to the session."
    references = (OWASP_LLM08, OWASP_LLM02)

    def evaluate(self, event, state):
        if event.event_type != "tool.call":
            return []
        resource_tenant = event.get(ev.RESOURCE_TENANT)
        if not resource_tenant or not state.tenant_id or resource_tenant == state.tenant_id:
            return []
        action = event.get(ev.ACTION_CLASS)
        severity = "critical" if action in ("write", "irreversible") else self.severity
        return [
            self.finding(
                event,
                state,
                f"Agent '{event.agent_id}' in a session bound to tenant '{state.tenant_id}' performed a "
                f"{action} via '{event.get(ev.TOOL_NAME)}' on '{event.get(ev.RESOURCE_URI, '?')}', "
                f"which belongs to tenant '{resource_tenant}'.",
                [event.event_id],
                severity=severity,
            )
        ]


class IrreversibleWithoutHumanApproval(Rule):
    rule_id = "AW-002"
    title = "Irreversible action without valid human approval"
    severity = "critical"
    description = "An irreversible tool call ran without a prior human approval bound to that exact tool call."
    response = "Treat as unauthorized change: suspend the agent credential, restore from backup, review approval gate."
    references = (OWASP_LLM06,)

    def evaluate(self, event, state):
        if event.event_type != "tool.call" or event.get(ev.ACTION_CLASS) != "irreversible":
            return []
        call_id = event.get(ev.TOOL_CALL_ID)
        tool = event.get(ev.TOOL_NAME)
        denial = state.denials.get(call_id)
        approval = state.approvals.get(call_id)
        if denial is not None:
            reason = f"approval was explicitly denied by '{denial.get(ev.APPROVER)}' and the call ran anyway"
            evidence = [denial.event_id, event.event_id]
        elif approval is None:
            reason = f"no approval event references tool call '{call_id}'"
            evidence = [event.event_id]
        elif approval.get(ev.APPROVER_TYPE) != "human":
            reason = (
                f"the approval came from {_a(approval.get(ev.APPROVER_TYPE))} principal "
                f"('{approval.get(ev.APPROVER)}'), not a human"
            )
            evidence = [approval.event_id, event.event_id]
        elif approval.get(ev.APPROVER) in (event.agent_id, *state.identity_bindings.keys()):
            reason = f"the approver '{approval.get(ev.APPROVER)}' is an agent in this session"
            evidence = [approval.event_id, event.event_id]
        else:
            return []
        return [
            self.finding(
                event,
                state,
                f"Irreversible tool '{tool}' executed by '{event.agent_id}': {reason}.",
                evidence,
            )
        ]


class UntrustedContentBeforePrivilegedAction(Rule):
    rule_id = "AW-003"
    title = "Privileged action shortly after untrusted content ingestion"
    severity = "high"
    description = (
        "A write, irreversible, or egress action followed ingestion of untrusted content in the same session. "
        "This is a behavioral indicator of indirect prompt injection, not proof of it."
    )
    response = "Confirm with the principal that the action was requested; inspect the ingested content for injected instructions."
    references = (OWASP_LLM01, OWASP_LLM06)

    def evaluate(self, event, state):
        if event.event_type != "tool.call" or event.get(ev.ACTION_CLASS) == "read":
            return []
        recent = [
            i for i in state.untrusted_ingests if event.timestamp - i.timestamp <= self.config.untrusted_window
        ]
        if not recent:
            return []
        sources = ", ".join(sorted({str(i.get(ev.SOURCE, "unknown source")) for i in recent}))
        return [
            self.finding(
                event,
                state,
                f"Agent '{event.agent_id}' performed {_a(event.get(ev.ACTION_CLASS))} action "
                f"('{event.get(ev.TOOL_NAME)}') within {int(self.config.untrusted_window.total_seconds() // 60)} "
                f"minutes of ingesting untrusted content from: {sources}.",
                [*(i.event_id for i in recent), event.event_id],
            )
        ]


# ---------------------------------------------------------------------------
# Sequence rules
# ---------------------------------------------------------------------------

Predicate = Callable[[AgentEvent, EngineConfig], bool]


class SequenceRule(Rule):
    """Fires when tool calls matching ``steps`` occur in order within a time window.

    Matching is greedy from the most recent call backwards, so the evidence is
    the latest call for each step that precedes the next step.
    """

    steps: tuple[Predicate, ...] = ()
    step_labels: tuple[str, ...] = ()

    def evaluate(self, event, state):
        if event.event_type != "tool.call" or not self.steps[-1](event, self.config):
            return []
        matched = [event]
        cursor = event
        prior = [c for c in reversed(state.tool_calls) if event.timestamp - c.timestamp <= self.config.sequence_window]
        remaining = list(self.steps[:-1])
        for call in prior:
            if not remaining:
                break
            if call.timestamp <= cursor.timestamp and remaining[-1](call, self.config):
                matched.append(call)
                cursor = call
                remaining.pop()
        if remaining:
            return []
        matched.reverse()
        path = " -> ".join(
            f"{label} ('{c.get(ev.TOOL_NAME)}')" for label, c in zip(self.step_labels, matched)
        )
        return [
            self.finding(
                event,
                state,
                f"Suspicious tool-call sequence by '{event.agent_id}': {path}, "
                f"within {int(self.config.sequence_window.total_seconds() // 60)} minutes.",
                [c.event_id for c in matched],
            )
        ]


def _sensitive_read(e: AgentEvent, _: EngineConfig) -> bool:
    return e.get(ev.ACTION_CLASS) == "read" and e.get(ev.SENSITIVITY) in SENSITIVE_LEVELS


def _unapproved_egress(e: AgentEvent, cfg: EngineConfig) -> bool:
    return e.get(ev.ACTION_CLASS) == "egress" and e.get(ev.DESTINATION) not in cfg.egress_allowlist


def _security_control_change(e: AgentEvent, _: EngineConfig) -> bool:
    return e.get(ev.TOOL_CATEGORY) == "security_control" and e.get(ev.ACTION_CLASS) in ("write", "irreversible")


def _irreversible(e: AgentEvent, _: EngineConfig) -> bool:
    return e.get(ev.ACTION_CLASS) == "irreversible"


class SensitiveReadThenEgress(SequenceRule):
    rule_id = "AW-004"
    title = "Sensitive data read followed by egress to non-allowlisted destination"
    severity = "critical"
    description = "Classic exfiltration shape: read confidential/secret data, then send data to a host not on the allowlist."
    response = "Block the destination, revoke the agent's egress capability, and scope the disclosure."
    references = (OWASP_LLM02, OWASP_LLM06)
    steps = (_sensitive_read, _unapproved_egress)
    step_labels = ("sensitive read", "egress to non-allowlisted host")


class ControlTamperingThenDestruction(SequenceRule):
    rule_id = "AW-005"
    title = "Security control change followed by irreversible action"
    severity = "critical"
    description = "An agent modified a security control (logging, alerting, policy) and then performed an irreversible action."
    response = "Restore the control, preserve evidence, suspend the agent, and review the delegated scopes."
    references = (OWASP_LLM06,)
    steps = (_security_control_change, _irreversible)
    step_labels = ("security control change", "irreversible action")


# ---------------------------------------------------------------------------
# Identity and delegation rules
# ---------------------------------------------------------------------------


class DelegationScopeEscalation(Rule):
    rule_id = "AW-006"
    title = "Delegation grants scopes the delegator does not hold"
    severity = "high"
    description = "Delegated scopes must be a subset of the delegating agent's scopes."
    response = "Reject the delegation at the token issuer; delegated tokens should only ever narrow scope."
    references = (OWASP_LLM06,)

    def evaluate(self, event, state):
        if event.event_type != "agent.delegate":
            return []
        parent = event.get(ev.PARENT_AGENT)
        child = event.get(ev.CHILD_AGENT)
        parent_scopes = state.agent_scopes.get(parent, frozenset())
        excess = sorted(set(event.get(ev.SCOPES)) - parent_scopes)
        if not excess:
            return []
        return [
            self.finding(
                event,
                state,
                f"'{parent}' delegated to '{child}' with scopes {excess} that '{parent}' does not hold "
                f"(parent scopes: {sorted(parent_scopes) or 'none recorded'}).",
                [event.event_id],
                agent_id=parent,
            )
        ]


class DelegationChainTooDeep(Rule):
    rule_id = "AW-007"
    title = "Delegation chain exceeds maximum depth"
    severity = "medium"
    description = "Long delegation chains lose accountability back to the human principal."
    response = "Cap delegation depth at the orchestrator and require re-authorization beyond the limit."
    references = (OWASP_LLM06,)

    def evaluate(self, event, state):
        if event.event_type != "agent.delegate":
            return []
        parent = event.get(ev.PARENT_AGENT)
        depth = state.delegation_depth(parent) + 1
        if depth <= self.config.max_delegation_depth:
            return []
        chain = " -> ".join([*state.delegation_chain(parent), event.get(ev.CHILD_AGENT)])
        return [
            self.finding(
                event,
                state,
                f"Delegation depth {depth} exceeds the configured maximum of "
                f"{self.config.max_delegation_depth}: {chain}.",
                [event.event_id],
                agent_id=parent,
            )
        ]


class WorkloadIdentityMismatch(Rule):
    rule_id = "AW-008"
    title = "Tool call from unbound or mismatched workload identity"
    severity = "high"
    description = "The workload identity on a tool call must match the identity bound to that agent in this session."
    response = "Quarantine the calling workload and verify how it obtained the agent's credentials."
    references = (OWASP_LLM06,)

    def evaluate(self, event, state):
        if event.event_type != "tool.call":
            return []
        observed = event.get(ev.WORKLOAD_ID)
        bound = state.identity_bindings.get(event.agent_id)
        if bound is None:
            return [
                self.finding(
                    event,
                    state,
                    f"Agent '{event.agent_id}' called '{event.get(ev.TOOL_NAME)}' but was never bound to a "
                    f"workload identity in this session (no session.start or agent.delegate for it).",
                    [event.event_id],
                    severity="medium",
                )
            ]
        if observed is not None and observed != bound:
            return [
                self.finding(
                    event,
                    state,
                    f"Agent '{event.agent_id}' is bound to workload '{bound}' but the call to "
                    f"'{event.get(ev.TOOL_NAME)}' came from '{observed}'.",
                    [event.event_id],
                )
            ]
        return []


class ToolOutsideDelegatedScope(Rule):
    rule_id = "AW-009"
    title = "Tool call outside the agent's delegated scopes"
    severity = "high"
    description = "The tool's required scope is not among the scopes the agent was granted."
    response = "Confirm the authorization layer enforces scopes; this call should have been denied upstream."
    references = (OWASP_LLM06,)

    def evaluate(self, event, state):
        if event.event_type != "tool.call":
            return []
        required = event.get(ev.REQUIRED_SCOPE)
        if not required or event.agent_id not in state.agent_scopes:
            return []
        granted = state.agent_scopes[event.agent_id]
        if required in granted:
            return []
        return [
            self.finding(
                event,
                state,
                f"'{event.agent_id}' called '{event.get(ev.TOOL_NAME)}', which requires scope '{required}'; "
                f"granted scopes are {sorted(granted) or 'none'}.",
                [event.event_id],
            )
        ]


class ToolCallBurst(Rule):
    rule_id = "AW-010"
    title = "Tool-call burst"
    severity = "low"
    description = "An agent exceeded the tool-call rate threshold, a sign of looping or scripted abuse."
    response = "Rate-limit the agent and check for a runaway loop."
    references = (OWASP_LLM10,)

    def evaluate(self, event, state):
        if event.event_type != "tool.call":
            return []
        window_start = event.timestamp - self.config.burst_window
        recent = [
            c for c in state.tool_calls if c.agent_id == event.agent_id and c.timestamp >= window_start
        ]
        # Fire exactly once per window, on the first call that exceeds the threshold.
        if len(recent) != self.config.burst_threshold:
            return []
        return [
            self.finding(
                event,
                state,
                f"'{event.agent_id}' made {len(recent) + 1} tool calls within "
                f"{int(self.config.burst_window.total_seconds())} seconds (threshold {self.config.burst_threshold}).",
                [*(c.event_id for c in recent[-5:]), event.event_id],
            )
        ]


RULE_CLASSES: tuple[type[Rule], ...] = (
    CrossTenantAccess,
    IrreversibleWithoutHumanApproval,
    UntrustedContentBeforePrivilegedAction,
    SensitiveReadThenEgress,
    ControlTamperingThenDestruction,
    DelegationScopeEscalation,
    DelegationChainTooDeep,
    WorkloadIdentityMismatch,
    ToolOutsideDelegatedScope,
    ToolCallBurst,
)


def default_rules(config: EngineConfig | None = None) -> list[Rule]:
    cfg = config or EngineConfig()
    return [cls(cfg) for cls in RULE_CLASSES]
