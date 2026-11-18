"""Shared data types."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Dict, List

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: len(SEVERITIES) - i for i, name in enumerate(SEVERITIES)}
CATEGORIES = ("security", "slop", "gap", "loose-end")


@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    confidence: str
    file: str
    line: int
    title: str
    detail: str = ""
    fix: str = ""
    snippet: str = ""
    source: str = "scanner"
    verdict: str = "unreviewed"
    verdict_reason: str = ""

    @property
    def id(self) -> str:
        """Stable across runs unless the rule, file or flagged text changes."""
        basis = "|".join((self.rule, self.file, " ".join(self.snippet.split()), self.title))
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:10]

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["id"] = self.id
        return data


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    agent: Dict[str, object] = field(default_factory=dict)

    def visible(self) -> List[Finding]:
        return [f for f in self.findings if f.verdict != "false_positive"]

    def sort(self) -> None:
        self.findings.sort(
            key=lambda f: (-SEVERITY_RANK[f.severity], f.category, f.file, f.line, f.rule)
        )
