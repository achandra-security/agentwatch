"""Detection engine: replays events per session through the rule set."""

from __future__ import annotations

from typing import Iterable

from .events import AgentEvent
from .rules import SEVERITY_ORDER, EngineConfig, Finding, Rule, default_rules
from .state import SessionState


class DetectionEngine:
    def __init__(self, config: EngineConfig | None = None, rules: list[Rule] | None = None):
        self.config = config or EngineConfig()
        self.rules = rules if rules is not None else default_rules(self.config)
        self.sessions: dict[str, SessionState] = {}

    def process(self, event: AgentEvent) -> list[Finding]:
        """Evaluate one event (streaming use). Rules see state *before* the event is applied."""
        state = self.sessions.setdefault(event.session_id, SessionState(event.session_id))
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(event, state))
        state.apply(event)
        return findings

    def analyze(self, events: Iterable[AgentEvent]) -> list[Finding]:
        ordered = sorted(events, key=lambda e: e.timestamp)
        findings: list[Finding] = []
        for event in ordered:
            findings.extend(self.process(event))
        return findings


def filter_findings(findings: Iterable[Finding], min_severity: str = "info") -> list[Finding]:
    floor = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]
