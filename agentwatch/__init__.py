"""agentwatch: behavioral detection for AI agent execution telemetry."""

from .engine import DetectionEngine, filter_findings
from .events import AgentEvent, EventValidationError, load_events, parse_events
from .rules import EngineConfig, Finding, default_rules

__all__ = [
    "AgentEvent",
    "DetectionEngine",
    "EngineConfig",
    "EventValidationError",
    "Finding",
    "default_rules",
    "filter_findings",
    "load_events",
    "parse_events",
]
__version__ = "0.1.0"
