# Architecture

## Design goals

1. **Explainability first.** Every finding must be understandable by an analyst without reading code. That means it states the observed values, the evidence event IDs, and the delegation chain.
2. **Deterministic.** Given the same events, the engine produces the same findings in the same order, whatever order the input arrives in. There are no model calls in the detection path.
3. **Point-in-time correctness.** Rules see session state as it was *before* the event under evaluation. This mirrors what an inline enforcement point could know, and it prevents an event from vouching for itself. For example, an approval arriving after the irreversible call does not count.
4. **Telemetry you can actually emit.** The schema needs only fields that a tool gateway, an approval service, and a retrieval layer already know.

## Components

```mermaid
flowchart TB
    subgraph ingest["events.py"]
        L[load_events / parse_events] --> VAL{schema valid?}
        VAL -- no --> ERR[EventValidationError<br/>file:line + reason]
        VAL -- yes --> SORT[stable sort by timestamp]
    end
    SORT --> ENG
    subgraph engine["engine.py"]
        ENG[DetectionEngine.process] --> LOOP[for each rule:<br/>rule.evaluate event, state]
        LOOP --> APPLY[state.apply event]
    end
    subgraph state["state.py: SessionState (one per session_id)"]
        T[tenant_id, principal_id]
        IB[identity_bindings<br/>agent -> workload id]
        SC[agent_scopes]
        DP[delegation_parent<br/>child -> parent]
        AP[approvals / denials<br/>by tool_call_id]
        UI[untrusted_ingests]
        TC[tool_calls history]
    end
    LOOP -. reads .-> state
    APPLY -. writes .-> state
    LOOP --> FND[Finding]
```

### Rule types

- **Point rules** (AW-001, AW-002, AW-006 to AW-009) inspect one event against the state.
- **Windowed rules** (AW-003, AW-010) compare the event to recent history inside a configurable time window.
- **Sequence rules** (AW-004, AW-005) subclass `SequenceRule`. They declare an ordered tuple of predicates and fire when the current tool call matches the last predicate and earlier calls in the same session match the others, in order, within `sequence_window`. Adding a new sequence takes about ten lines:

```python
class SecretsThenNewTool(SequenceRule):
    rule_id, title, severity = "AW-100", "Secret read then first-seen tool", "high"
    steps = (lambda e, c: e.get("agentwatch.data.sensitivity") == "secret",
             lambda e, c: e.get("gen_ai.tool.name") not in KNOWN_TOOLS)
    step_labels = ("secret read", "unknown tool")
```

### Identity and delegation model

- `session.start` binds the root agent to a workload identity (for example a SPIFFE ID string) and records its scopes, the principal, and the tenant.
- `agent.delegate` records a parent-to-child edge, the child's scopes, and optionally the child's workload identity.
- `delegation_chain(agent)` walks parent edges back to the root, with a cycle guard. Findings include this chain so an analyst can see which human principal ultimately owns the action.

## Where it sits in a real deployment

```mermaid
flowchart LR
    U[User] --> ORCH[Orchestrator agent]
    ORCH -->|delegates| SUB[Sub-agents]
    ORCH & SUB --> GW[Tool gateway<br/>authorization + approval]
    GW --> TOOLS[(Tools / APIs / data)]
    GW -->|emit events| COL[OTel collector or<br/>log shipper]
    RET[Retrieval layer] -->|content.ingest with<br/>provenance labels| COL
    COL --> AW[agentwatch<br/>stream or batch]
    AW -->|alerts| SIEM[(LogScale / Splunk)]
    SIEM --> SOC[SOC triage and response]
```

The tool gateway is the right place to emit `tool.call`, `approval.*`, and identity fields. It sits outside the agent's control and already knows the verified caller identity. The agent process itself should be treated as untrusted.

## Complexity

Per event, point rules run in O(1). Windowed and sequence rules scan the session's tool-call history, which is O(n) per event in the worst case. That is acceptable for reference use and for sessions of hundreds of calls. A production stream processor would keep bounded windows instead.
