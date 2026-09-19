from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 50,
            Severity.HIGH: 40,
            Severity.MEDIUM: 30,
            Severity.LOW: 20,
            Severity.INFO: 10,
        }[self]


class SourceKind(str, Enum):
    RULE = "rule"
    LLM = "llm"
    HEURISTIC = "heuristic"


class Finding(BaseModel):
    rule_id: str
    title: str
    message: str
    suggestion: str
    severity: Severity
    file: str
    line: int
    column: int = 1
    end_line: int | None = None
    snippet: str = ""
    source: SourceKind = SourceKind.RULE
    confidence: float = 0.85
    cwe: str | None = None
    category: str = "quality"

    def fingerprint(self) -> str:
        return f"{self.rule_id}:{self.file}:{self.line}:{self.title}"


class FileSummary(BaseModel):
    path: str
    finding_count: int
    highest_severity: Severity | None = None


class ReviewReport(BaseModel):
    tool: str = "java-ai-code-reviewer"
    version: str = "0.1.0"
    scanned_files: int = 0
    findings: list[Finding] = Field(default_factory=list)
    files: list[FileSummary] = Field(default_factory=list)
    llm_used: bool = False
    scan_mode: str = "rules"
    risk_score: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped

    def count(self, severity: Severity) -> int:
        return sum(1 for item in self.findings if item.severity == severity)

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda item: item.severity.rank).severity
