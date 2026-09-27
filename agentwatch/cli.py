"""Command-line interface.

    agentwatch analyze fixtures/indirect_injection_exfil.jsonl
    agentwatch analyze fixtures/*.jsonl --format ndjson --min-severity high
    agentwatch analyze session.jsonl --fail-on high     # non-zero exit for CI gating
    agentwatch rules
"""

from __future__ import annotations

import argparse
import sys

from .engine import DetectionEngine, filter_findings
from .events import EventValidationError, load_events
from .output import to_hec, to_json, to_ndjson, to_text
from .rules import RULE_CLASSES, SEVERITY_ORDER, EngineConfig

SEVERITIES = list(SEVERITY_ORDER)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentwatch", description="Behavioral detection for AI agent telemetry.")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analyze one or more JSONL event files")
    analyze.add_argument("paths", nargs="+")
    analyze.add_argument("--format", choices=["text", "json", "ndjson", "hec"], default="text")
    analyze.add_argument("--min-severity", choices=SEVERITIES, default="info")
    analyze.add_argument(
        "--allow-egress",
        action="append",
        default=[],
        metavar="HOST",
        help="destination host that egress may reach without an AW-004 finding (repeatable)",
    )
    analyze.add_argument("--max-delegation-depth", type=int, default=2)
    analyze.add_argument(
        "--fail-on", choices=SEVERITIES, help="exit with status 2 if any finding is at or above this severity"
    )

    sub.add_parser("rules", help="list detection rules")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "rules":
        for cls in RULE_CLASSES:
            print(f"{cls.rule_id}  [{cls.severity:<8}]  {cls.title}")
            print(f"        {cls.description}")
        return 0

    config = EngineConfig(
        egress_allowlist=frozenset(args.allow_egress),
        max_delegation_depth=args.max_delegation_depth,
    )
    events = []
    try:
        for path in args.paths:
            events.extend(load_events(path))
    except (OSError, EventValidationError) as exc:
        print(f"agentwatch: error: {exc}", file=sys.stderr)
        return 1

    findings = filter_findings(DetectionEngine(config).analyze(events), args.min_severity)

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "ndjson":
        if findings:
            print(to_ndjson(findings))
    elif args.format == "hec":
        if findings:
            print(to_hec(findings))
    else:
        print(to_text(findings, len(events), args.paths))

    if args.fail_on and any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
