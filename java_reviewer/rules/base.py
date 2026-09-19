from __future__ import annotations

from abc import ABC, abstractmethod

from java_reviewer.analyze.source import JavaCompilationUnit
from java_reviewer.analyze.xml import XmlDocument
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity, SourceKind


class Rule(ABC):
    rule_id: str
    title: str
    category: str
    default_severity: Severity
    cwe: str | None = None

    @abstractmethod
    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        return []

    def check_xml(self, document: XmlDocument, config: ReviewConfig) -> list[Finding]:
        return []

    def finding(
        self,
        *,
        file: str,
        line: int,
        message: str,
        suggestion: str,
        snippet: str = "",
        severity: Severity | None = None,
        title: str | None = None,
        source: SourceKind = SourceKind.RULE,
        confidence: float = 0.9,
        column: int = 1,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            message=message,
            suggestion=suggestion,
            severity=severity or self.default_severity,
            file=file,
            line=max(1, line),
            column=column,
            snippet=snippet,
            source=source,
            confidence=confidence,
            cwe=self.cwe,
            category=self.category,
        )
