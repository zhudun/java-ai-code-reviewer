from __future__ import annotations

import re

from java_reviewer.analyze.source import JavaCompilationUnit
from java_reviewer.analyze.xml import XmlDocument
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule

SQL_HINT = r"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b"
SQL_CALLS = (
    r"createNativeQuery",
    r"createQuery",
    r"createSQLQuery",
    r"jdbcTemplate\.(?:query|update|execute|batchUpdate)",
    r"namedParameterJdbcTemplate\.(?:query|update)",
    r"Statement\.execute",
    r"\.executeQuery",
    r"\.executeUpdate",
    r"\.execute\s*\(",
)


class SqlInjectionRule(Rule):
    rule_id = "java.sql-injection"
    title = "SQL 注入风险"
    category = "security"
    default_severity = Severity.CRITICAL
    cwe = "CWE-89"

    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        for cls in unit.classes:
            for method in cls.methods:
                for line_no in range(method.start_line, method.end_line + 1):
                    text = unit.clean_lines[line_no - 1] if line_no <= len(unit.clean_lines) else ""
                    findings.extend(self._line(unit, line_no, text, method.body))
        # also scan whole file for string-built SQL assigned across lines
        joined = "\n".join(unit.clean_lines)
        for match in re.finditer(
            rf"({ '|'.join(SQL_CALLS) })\s*\(\s*([^)]+)\)",
            joined,
            re.I,
        ):
            arg = match.group(2)
            if _unsafe_sql_expr(arg):
                line = unit.clean[: match.start()].count("\n") + 1
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line,
                        snippet=unit.snippet(line),
                        message="SQL / JPQL 通过字符串拼接构造，存在注入风险。",
                        suggestion="使用 PreparedStatement、命名参数或 MyBatis `#{}` 绑定，禁止拼接用户输入。",
                    )
                )
        return _unique(findings)

    def check_xml(self, document: XmlDocument, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        name = document.path.lower()
        if not any(token in name for token in ("mapper", "dao", ".xml")):
            return findings
        for idx, line in enumerate(document.lines, start=1):
            if re.search(r"\$\{[^}]+\}", line):
                findings.append(
                    self.finding(
                        file=document.path,
                        line=idx,
                        snippet=_xml_snippet(document, idx),
                        message="MyBatis `${}` 会把参数直接拼进 SQL，属于经典注入点。",
                        suggestion="改用 `#{}` 预编译绑定。排序字段等动态列名必须做白名单校验。",
                    )
                )
            if re.search(r"LIKE\s+'%'\s*\+|LIKE\s+\"%\"\s*\+", line, re.I):
                findings.append(
                    self.finding(
                        file=document.path,
                        line=idx,
                        snippet=_xml_snippet(document, idx),
                        message="LIKE 子句使用字符串拼接，可能被注入通配符或 SQL 片段。",
                        suggestion="使用 `#{}` 绑定关键字，在 Java 层转义 `%` / `_`。",
                    )
                )
        return findings

    def _line(
        self,
        unit: JavaCompilationUnit,
        line_no: int,
        text: str,
        body: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if re.search(SQL_HINT, text, re.I) and ("+" in text or "String.format" in text):
            if re.search(r"['\"]\s*\+|String\.format\s*\(\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)", text, re.I):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message="SQL 字符串与变量拼接，攻击者可注入任意子句。",
                        suggestion="改为参数绑定：`WHERE name = ?` + PreparedStatement.setString。",
                    )
                )
        if "String.format" in text and re.search(SQL_HINT, text, re.I):
            findings.append(
                self.finding(
                    file=unit.path,
                    line=line_no,
                    snippet=unit.snippet(line_no),
                    message="使用 String.format 组装 SQL，格式化参数不会被转义。",
                    suggestion="使用 ? 占位符或命名参数，不要把用户输入写进格式化串。",
                )
            )
        if re.search(r"Statement\s+\w+\s*=\s*\w+\.createStatement\s*\(", text):
            if re.search(r"\.execute(?:Query|Update)?\s*\(\s*\w+", body):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message="使用 java.sql.Statement 动态执行字符串 SQL。",
                        suggestion="改用 PreparedStatement，并对每个参数 setXxx。",
                    )
                )
        return findings


def _unsafe_sql_expr(expr: str) -> bool:
    if "+" in expr and re.search(r"[\"'].*[\"']", expr):
        return True
    if "String.format" in expr or "StringBuilder" in expr or "append(" in expr:
        return True
    if re.search(r"\$\{", expr):
        return True
    return False


def _xml_snippet(document: XmlDocument, line: int, radius: int = 2) -> str:
    start = max(1, line - radius)
    end = min(len(document.lines), line + radius)
    rows = []
    for idx in range(start, end + 1):
        prefix = ">" if idx == line else " "
        rows.append(f"{prefix} {idx:>4} | {document.lines[idx - 1]}")
    return "\n".join(rows)


def _unique(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for item in findings:
        key = item.fingerprint()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
