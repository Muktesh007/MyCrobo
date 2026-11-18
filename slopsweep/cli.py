"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .agent import DEFAULT_MODEL, run_agent
from .models import CATEGORIES, SEVERITIES, SEVERITY_RANK
from .report import RENDERERS
from .rules import RULES, STRUCTURAL_RULES
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopsweep",
        description="Find security issues, slop, coding gaps and loose ends in any codebase.",
    )
    parser.add_argument("path", nargs="?", default=".", help="repository to scan (default: .)")
    parser.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    parser.add_argument("-o", "--output", help="write the report to this file")
    parser.add_argument("--category", action="append", choices=CATEGORIES,
                        help="limit the report to a category (repeatable)")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="info")
    parser.add_argument("--fail-on", choices=SEVERITIES,
                        help="exit 1 if a finding is at or above this severity")
    parser.add_argument("--agent", action="store_true",
                        help="have Claude verify findings and look for deeper issues")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="high")
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--show-dismissed", action="store_true",
                        help="include findings the agent marked as false positives")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--version", action="version", version=f"slopsweep {__version__}")
    return parser


def list_rules() -> str:
    rows = [f"{r.id}  {r.category:10} {r.severity:9} {r.title}" for r in RULES]
    rows += [f"{key}  {category:10} {'varies':9} {title}"
             for key, (category, title) in STRUCTURAL_RULES.items()]
    return "\n".join(sorted(rows)) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    try:
        code = run(argv)
        sys.stdout.flush()
        return code
    except BrokenPipeError:  # the reader closed early, as `| head` does
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


def run(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    if args.list_rules:
        sys.stdout.write(list_rules())
        return 0
    if not os.path.isdir(args.path):
        print(f"slopsweep: not a directory: {args.path}", file=sys.stderr)
        return 2

    result, repo = scan(args.path)
    if args.agent:
        print(f"Reviewing {len(result.findings)} candidates with {args.model}. "
              "Masked code excerpts are sent to the Claude API.", file=sys.stderr)
        outcome = run_agent(result, repo, model=args.model, effort=args.effort,
                            max_steps=args.max_steps,
                            log=lambda message: print(message, file=sys.stderr))
        if outcome["status"] != "complete":
            print(f"Agent review {outcome['status']}: {outcome['summary']} "
                  "Scanner results are still reported.", file=sys.stderr)

    floor = SEVERITY_RANK[args.min_severity]
    pool = result.findings if args.show_dismissed else result.visible()
    findings = [f for f in pool if SEVERITY_RANK[f.severity] >= floor
                and (not args.category or f.category in args.category)]
    rendered = RENDERERS[args.format](result, findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0
