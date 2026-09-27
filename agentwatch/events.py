"""Normalized agent security telemetry.

Events are flat attribute maps, in the style of OpenTelemetry span attributes.
Keys in the ``gen_ai.*`` namespace reuse names from the OpenTelemetry GenAI
semantic conventions (agent and tool spans). Keys in the ``agentwatch.*``
namespace are security extensions defined by this project; they are not part
of any OpenTelemetry specification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# --- OpenTelemetry GenAI semantic-convention attribute names -------------
AGENT_ID = "gen_ai.agent.id"
AGENT_NAME = "gen_ai.agent.name"
OPERATION = "gen_ai.operation.name"
TOOL_NAME = "gen_ai.tool.name"
TOOL_CALL_ID = "gen_ai.tool.call.id"

# --- agentwatch security extensions ---------------------------------------
WORKLOAD_ID = "agentwatch.workload.id"            # e.g. a SPIFFE ID string
PRINCIPAL = "agentwatch.principal.id"             # human/user the agent acts for
TENANT = "agentwatch.tenant.id"                   # tenant bound to the session
RESOURCE_URI = "agentwatch.resource.uri"
RESOURCE_TENANT = "agentwatch.resource.tenant"    # tenant that owns the resource
ACTION_CLASS = "agentwatch.tool.action_class"     # read | write | irreversible | egress
TOOL_CATEGORY = "agentwatch.tool.category"        # free-form, e.g. security_control
REQUIRED_SCOPE = "agentwatch.tool.required_scope"
SENSITIVITY = "agentwatch.data.sensitivity"       # public | internal | confidential | secret
DESTINATION = "agentwatch.egress.destination"     # host the data is sent to
TRUST = "agentwatch.provenance.trust"             # trusted | untrusted
SOURCE = "agentwatch.provenance.source"           # where ingested content came from
SCOPES = "agentwatch.delegation.scopes"
PARENT_AGENT = "agentwatch.delegation.parent_agent_id"
CHILD_AGENT = "agentwatch.delegation.child_agent_id"
CHILD_WORKLOAD = "agentwatch.delegation.child_workload_id"
APPROVER = "agentwatch.approval.approver_id"
APPROVER_TYPE = "agentwatch.approval.approver_type"  # human | agent | system

EVENT_TYPES = frozenset(
    {
        "session.start",
        "content.ingest",
        "tool.call",
        "agent.delegate",
        "approval.granted",
        "approval.denied",
    }
)
ACTION_CLASSES = frozenset({"read", "write", "irreversible", "egress"})

_REQUIRED_ATTRS = {
    "session.start": (AGENT_ID, WORKLOAD_ID, PRINCIPAL, TENANT),
    "content.ingest": (AGENT_ID, TRUST),
    "tool.call": (AGENT_ID, TOOL_NAME, TOOL_CALL_ID, ACTION_CLASS),
    "agent.delegate": (PARENT_AGENT, CHILD_AGENT, SCOPES),
    "approval.granted": (TOOL_CALL_ID, APPROVER, APPROVER_TYPE),
    "approval.denied": (TOOL_CALL_ID, APPROVER, APPROVER_TYPE),
}


class EventValidationError(ValueError):
    """Raised when an input record does not match the event schema."""


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise EventValidationError(f"timestamp must be an ISO-8601 string, got {value!r}")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EventValidationError(f"invalid timestamp {value!r}") from exc
    if ts.tzinfo is None:
        raise EventValidationError(f"timestamp {value!r} must include a timezone")
    return ts


@dataclass(frozen=True)
class AgentEvent:
    event_id: str
    timestamp: datetime
    session_id: str
    event_type: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    @property
    def agent_id(self) -> str | None:
        return self.attributes.get(AGENT_ID)

    @property
    def iso_timestamp(self) -> str:
        return self.timestamp.isoformat().replace("+00:00", "Z")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentEvent":
        if not isinstance(raw, dict):
            raise EventValidationError("event must be a JSON object")
        missing = [k for k in ("event_id", "timestamp", "session_id", "event_type") if k not in raw]
        if missing:
            raise EventValidationError(f"missing required fields: {', '.join(missing)}")
        event_type = raw["event_type"]
        if event_type not in EVENT_TYPES:
            raise EventValidationError(f"unknown event_type {event_type!r}")
        attributes = raw.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise EventValidationError("attributes must be an object")
        absent = [k for k in _REQUIRED_ATTRS[event_type] if k not in attributes]
        if absent:
            raise EventValidationError(f"{event_type} event missing attributes: {', '.join(absent)}")
        if event_type == "tool.call" and attributes[ACTION_CLASS] not in ACTION_CLASSES:
            raise EventValidationError(
                f"invalid {ACTION_CLASS} {attributes[ACTION_CLASS]!r}; expected one of {sorted(ACTION_CLASSES)}"
            )
        if SCOPES in attributes and not isinstance(attributes[SCOPES], list):
            raise EventValidationError(f"{SCOPES} must be a list")
        return cls(
            event_id=str(raw["event_id"]),
            timestamp=parse_timestamp(raw["timestamp"]),
            session_id=str(raw["session_id"]),
            event_type=event_type,
            attributes=dict(attributes),
        )


def parse_events(records: Iterable[dict[str, Any]]) -> list[AgentEvent]:
    events = [AgentEvent.from_dict(r) for r in records]
    return sorted(events, key=lambda e: e.timestamp)  # stable: ties keep input order


def load_events(path: str | Path) -> list[AgentEvent]:
    """Load a JSON Lines file of events. Blank lines and ``#`` comments are ignored."""
    events: list[AgentEvent] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw = json.loads(line)
                events.append(AgentEvent.from_dict(raw))
            except json.JSONDecodeError as exc:
                raise EventValidationError(f"{path}:{lineno}: invalid JSON ({exc.msg})") from exc
            except EventValidationError as exc:
                raise EventValidationError(f"{path}:{lineno}: {exc}") from exc
    return sorted(events, key=lambda e: e.timestamp)
