from __future__ import annotations

from java_reviewer.models import Finding, FileSummary, ReviewReport, Severity

_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def build_report(
    findings: list[Finding],
    scanned_files: int,
    llm_used: bool,
    scan_mode: str,
) -> ReviewReport:
    findings = sorted(findings, key=lambda item: (-item.severity.rank, item.file, item.line))
    by_file: dict[str, list[Finding]] = {}
    for item in findings:
        by_file.setdefault(item.file, []).append(item)
    files = []
    for path, items in sorted(by_file.items()):
        highest = max(items, key=lambda item: item.severity.rank).severity
        files.append(FileSummary(path=path, finding_count=len(items), highest_severity=highest))
    score = min(100, sum(_WEIGHT[item.severity] for item in findings))
    return ReviewReport(
        scanned_files=scanned_files,
        findings=findings,
        files=files,
        llm_used=llm_used,
        scan_mode=scan_mode,
        risk_score=score,
    )
