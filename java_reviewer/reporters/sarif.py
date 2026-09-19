from __future__ import annotations

import json

from java_reviewer.models import ReviewReport, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(report: ReviewReport) -> str:
    rules = {}
    results = []
    for item in report.findings:
        rules[item.rule_id] = {
            "id": item.rule_id,
            "name": item.title,
            "shortDescription": {"text": item.title},
            "fullDescription": {"text": item.message},
            "help": {"text": item.suggestion},
            "properties": {"category": item.category, "cwe": item.cwe},
            "defaultConfiguration": {"level": _LEVEL[item.severity]},
        }
        results.append(
            {
                "ruleId": item.rule_id,
                "level": _LEVEL[item.severity],
                "message": {"text": f"{item.message} 修复：{item.suggestion}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item.file.replace("\\", "/")},
                            "region": {
                                "startLine": item.line,
                                "startColumn": item.column,
                                "snippet": {"text": item.snippet},
                            },
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "java-ai-code-reviewer",
                        "version": report.version,
                        "informationUri": "https://github.com/zhudun/java-ai-code-reviewer",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2)
