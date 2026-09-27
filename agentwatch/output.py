"""Render findings as a text report, JSON, or SIEM-ready NDJSON."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Iterable

from .rules import SEVERITY_ORDER, Finding

# Numeric severities on a 0-100 scale for SIEMs that sort or threshold numerically.
SEVERITY_SCORE = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}


def to_json(findings: Iterable[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def to_siem_record(finding: Finding) -> dict:
    """One flat-ish alert record. Field names loosely follow Elastic Common Schema conventions
    so they map cleanly into LogScale or Splunk field extraction."""
    return {
        "@timestamp": finding.timestamp,
        "event.kind": "alert",
        "event.module": "agentwatch",
        "event.dataset": "agentwatch.findings",
        "rule.id": finding.rule_id,
        "rule.name": finding.title,
        "event.severity": SEVERITY_SCORE[finding.severity],
        "agentwatch.severity": finding.severity,
        "agentwatch.session_id": finding.session_id,
        "gen_ai.agent.id": finding.agent_id,
        "agentwatch.delegation_chain": list(finding.delegation_chain),
        "agentwatch.evidence_event_ids": list(finding.evidence),
        "message": finding.explanation,
        "agentwatch.response": finding.response,
    }


def to_ndjson(findings: Iterable[Finding]) -> str:
    return "\n".join(json.dumps(to_siem_record(f), sort_keys=True) for f in findings)


def to_hec(findings: Iterable[Finding], sourcetype: str = "agentwatch:finding") -> str:
    """Newline-delimited HTTP Event Collector envelopes.

    The same envelope shape is accepted by Splunk HEC (``/services/collector/event``) and by
    Falcon LogScale's HEC-compatible ingest endpoint. Shipping is left to the caller; this
    function only formats, so no credentials or network access are involved.
    """
    lines = []
    for f in findings:
        epoch = datetime.fromisoformat(f.timestamp.replace("Z", "+00:00")).timestamp()
        lines.append(
            json.dumps(
                {"time": epoch, "source": "agentwatch", "sourcetype": sourcetype, "event": to_siem_record(f)},
                sort_keys=True,
            )
        )
    return "\n".join(lines)


def to_text(findings: list[Finding], event_count: int, sources: list[str]) -> str:
    lines = [
        "agentwatch detection report",
        "=" * 27,
        f"inputs: {', '.join(sources)}",
        f"events analyzed: {event_count}",
        f"findings: {len(findings)}",
    ]
    if findings:
        counts = Counter(f.severity for f in findings)
        ordered = sorted(counts, key=lambda s: -SEVERITY_ORDER[s])
        lines.append("by severity: " + ", ".join(f"{s}={counts[s]}" for s in ordered))
    for f in sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.timestamp)):
        lines += [
            "",
            f"[{f.severity.upper()}] {f.rule_id} {f.title}",
            f"  session:  {f.session_id}",
            f"  agent:    {f.agent_id}"
            + (f"  (chain: {' -> '.join(f.delegation_chain)})" if len(f.delegation_chain) > 1 else ""),
            f"  when:     {f.timestamp}",
            f"  why:      {f.explanation}",
            f"  evidence: {', '.join(f.evidence)}",
            f"  respond:  {f.response}",
        ]
    return "\n".join(lines)
