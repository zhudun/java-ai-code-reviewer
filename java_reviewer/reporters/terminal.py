from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from java_reviewer.models import ReviewReport, Severity

_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def render_terminal(report: ReviewReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print()
    console.print(
        Panel.fit(
            f"[bold]Java AI Code Reviewer[/bold]  ·  {report.scan_mode}\n"
            f"扫描文件 {report.scanned_files}  ·  发现问题 {len(report.findings)}  ·  "
            f"风险分 {report.risk_score}",
            border_style="magenta",
        )
    )

    table = Table(title="按风险等级", show_lines=False)
    table.add_column("等级")
    table.add_column("数量", justify="right")
    for severity in Severity:
        count = report.count(severity)
        table.add_row(Text(severity.value, style=_COLORS[severity]), str(count))
    console.print(table)

    grouped = report.findings_by_severity()
    for severity in Severity:
        items = grouped[severity]
        if not items:
            continue
        console.print()
        console.print(Text(f"▸ {severity.value}", style=_COLORS[severity]))
        for item in items:
            console.print(
                f"  [{_COLORS[severity]}]{item.rule_id}[/{_COLORS[severity]}]  "
                f"{item.file}:{item.line}  {item.title}"
            )
            console.print(f"    {item.message}")
            if item.snippet:
                console.print(Text(item.snippet, style="dim"))
            console.print(f"    修复: {item.suggestion}")
            console.print()
