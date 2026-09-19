from __future__ import annotations

from pathlib import Path

from java_reviewer.analyze.source import parse_java
from java_reviewer.analyze.xml import parse_xml_text
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule
from java_reviewer.rules.npe import NullPointerRule
from java_reviewer.rules.resource_leak import ResourceLeakRule
from java_reviewer.rules.sql_injection import SqlInjectionRule
from java_reviewer.rules.thread_safety import ThreadSafetyRule
from java_reviewer.rules.transaction import TransactionBoundaryRule


def default_rules() -> list[Rule]:
    return [
        NullPointerRule(),
        ResourceLeakRule(),
        ThreadSafetyRule(),
        TransactionBoundaryRule(),
        SqlInjectionRule(),
    ]


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or default_rules()

    def analyze_file(self, path: Path, config: ReviewConfig) -> list[Finding]:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = str(path)
        findings: list[Finding] = []
        if path.suffix == ".java":
            unit = parse_java(relative, text)
            for rule in self.rules:
                if not config.rule_enabled(rule.rule_id):
                    continue
                findings.extend(rule.check_java(unit, config))
        elif path.suffix == ".xml":
            document = parse_xml_text(relative, text)
            for rule in self.rules:
                if not config.rule_enabled(rule.rule_id):
                    continue
                findings.extend(rule.check_xml(document, config))
        return [_apply_severity(item, config) for item in findings]


def _apply_severity(finding: Finding, config: ReviewConfig) -> Finding:
    override = config.override_severity(finding.rule_id)
    if override:
        finding.severity = Severity(override)
    return finding
