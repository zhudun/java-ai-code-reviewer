from __future__ import annotations

from java_reviewer.models import ReviewReport, Severity

_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render_markdown(report: ReviewReport) -> str:
    lines = [
        "# Java AI 代码审查报告",
        "",
        f"- 扫描文件：{report.scanned_files}",
        f"- 发现问题：{len(report.findings)}",
        f"- 风险分：{report.risk_score} / 100",
        f"- 模式：`{report.scan_mode}`",
        f"- LLM：{'已启用' if report.llm_used else '未启用（启发式上下文审查）'}",
        "",
        "## 风险概览",
        "",
        "| 等级 | 数量 |",
        "| --- | ---: |",
    ]
    for severity in Severity:
        lines.append(f"| {_EMOJI[severity]} {severity.value} | {report.count(severity)} |")
    lines.append("")

    if not report.findings:
        lines.append("未发现需要报告的问题。")
        return "\n".join(lines)

    grouped = report.findings_by_severity()
    for severity in Severity:
        items = grouped[severity]
        if not items:
            continue
        lines.append(f"## {_EMOJI[severity]} {severity.value}")
        lines.append("")
        for item in items:
            loc = f"{item.file}:{item.line}"
            lines.append(f"### {item.title}")
            lines.append("")
            lines.append(f"- 规则：`{item.rule_id}`")
            lines.append(f"- 位置：`{loc}`")
            lines.append(f"- 来源：{item.source.value}")
            if item.cwe:
                lines.append(f"- CWE：{item.cwe}")
            lines.append(f"- 说明：{item.message}")
            lines.append(f"- 修复建议：{item.suggestion}")
            if item.snippet:
                lines.append("")
                lines.append("```text")
                lines.append(item.snippet)
                lines.append("```")
            lines.append("")
    return "\n".join(lines)
