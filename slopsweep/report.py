"""Report renderers."""

from __future__ import annotations

import json
from collections import Counter
from typing import List

from . import __version__
from .models import CATEGORIES, SEVERITIES, Finding, ScanResult

LABELS = {"security": "Security", "slop": "Slop", "gap": "Coding gaps", "loose-end": "Loose ends"}


def _where(finding: Finding) -> str:
    return f"{finding.file}:{finding.line}" if finding.line else finding.file


def _counts(findings: List[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    return ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]) or "none"


def _agent_lines(result: ScanResult) -> List[str]:
    agent = result.agent
    if not agent:
        return []
    dismissed = sum(1 for f in result.findings if f.verdict == "false_positive")
    confirmed = sum(1 for f in result.findings if f.verdict == "confirmed")
    added = sum(1 for f in result.findings if f.source == "agent")
    lines = [f"Agent review: {agent['status']} ({agent['steps']} steps). "
             f"{confirmed} confirmed, {dismissed} dismissed, {added} added."]
    if agent.get("summary"):
        lines.append(str(agent["summary"]))
    return lines


def render_text(result: ScanResult, findings: List[Finding]) -> str:
    out = [f"SlopSweep {__version__}: {result.root}",
           f"{result.files_scanned} files scanned, {len(findings)} findings ({_counts(findings)})"]
    out.extend(_agent_lines(result))
    for category in CATEGORIES:
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        out.extend(["", f"== {LABELS[category]} ({len(group)}) =="])
        for f in group:
            mark = "" if f.verdict == "unreviewed" else f" [{f.verdict}]"
            out.append(f"{f.severity.upper():8} {f.rule}  {_where(f)}  {f.title}{mark}")
            if f.snippet:
                out.append(f"         > {f.snippet}")
            if f.detail:
                out.append(f"         {f.detail}")
            if f.verdict_reason and f.source != "agent":
                out.append(f"         Review: {f.verdict_reason}")
            if f.fix:
                out.append(f"         Fix: {f.fix}")
    return "\n".join(out) + "\n"


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult, findings: List[Finding]) -> str:
    out = ["# SlopSweep report", "",
           f"{result.files_scanned} files scanned. **{len(findings)} findings** ({_counts(findings)}).", ""]
    agent = _agent_lines(result)
    if agent:
        out.extend(agent + [""])
    for category in CATEGORIES:
        group = [f for f in findings if f.category == category]
        if not group:
            continue
        out.extend([f"## {LABELS[category]} ({len(group)})", "",
                    "| Severity | Rule | Location | Issue | Fix |", "|---|---|---|---|---|"])
        for f in group:
            issue = f.title + (f": {f.detail}" if f.detail else "")
            out.append(f"| {f.severity} | {f.rule} | `{_cell(_where(f))}` | {_cell(issue)} | {_cell(f.fix)} |")
        out.append("")
    return "\n".join(out)


def render_json(result: ScanResult, findings: List[Finding]) -> str:
    return json.dumps({
        "tool": "slopsweep", "version": __version__, "root": result.root,
        "files_scanned": result.files_scanned, "languages": result.languages,
        "summary": dict(Counter(f.severity for f in findings)),
        "agent": result.agent, "findings": [f.to_dict() for f in findings],
    }, indent=2) + "\n"


def render_sarif(result: ScanResult, findings: List[Finding]) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = {f.rule: f.title for f in findings}
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "SlopSweep", "version": __version__,
                "rules": [{"id": k, "shortDescription": {"text": v}} for k, v in sorted(rules.items())],
            }},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": " ".join(p for p in (f.title, f.detail, f.fix) if p)},
                "partialFingerprints": {"slopsweep": f.id},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)},
                }}],
            } for f in findings],
        }],
    }, indent=2) + "\n"


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json,
             "sarif": render_sarif}
