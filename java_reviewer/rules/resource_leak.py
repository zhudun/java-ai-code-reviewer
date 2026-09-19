from __future__ import annotations

import re

from java_reviewer.analyze.source import JavaCompilationUnit, JavaMethod
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule

RESOURCE_TYPES = (
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "BufferedInputStream",
    "BufferedOutputStream",
    "BufferedReader",
    "BufferedWriter",
    "InputStreamReader",
    "OutputStreamWriter",
    "ObjectInputStream",
    "ObjectOutputStream",
    "ZipInputStream",
    "ZipOutputStream",
    "GZIPInputStream",
    "GZIPOutputStream",
    "Socket",
    "ServerSocket",
    "DatagramSocket",
    "Scanner",
    "JarFile",
    "ZipFile",
    "PrintWriter",
    "PrintStream",
)

JDBC_FACTORIES = (
    r"DriverManager\.getConnection",
    r"\.createStatement\s*\(",
    r"\.prepareStatement\s*\(",
    r"\.prepareCall\s*\(",
    r"\.executeQuery\s*\(",
)


class ResourceLeakRule(Rule):
    rule_id = "java.resource-leak"
    title = "资源未关闭"
    category = "reliability"
    default_severity = Severity.HIGH
    cwe = "CWE-772"

    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        for cls in unit.classes:
            for method in cls.methods:
                findings.extend(self._scan_method(unit, method))
        return findings

    def _scan_method(self, unit: JavaCompilationUnit, method: JavaMethod) -> list[Finding]:
        findings: list[Finding] = []
        try_with = _try_with_resources(method.body)
        for line_no in range(method.start_line, method.end_line + 1):
            text = unit.clean_lines[line_no - 1] if line_no <= len(unit.clean_lines) else ""
            for rtype in RESOURCE_TYPES:
                ctor = re.search(rf"\bnew\s+{rtype}\s*\(", text)
                assign = re.search(rf"\b{rtype}\s+(\w+)\s*=", text)
                if not ctor and not assign:
                    continue
                var = assign.group(1) if assign else None
                if _in_try_with(text, try_with, var, rtype):
                    continue
                if var and _closed(method.body, var):
                    continue
                if "try (" in method.body and rtype in try_with:
                    continue
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message=f"`{rtype}` 未使用 try-with-resources，也未见可靠的 close()。",
                        suggestion=f"使用 try ({rtype} resource = ...) {{ ... }}，避免 finally 漏关或异常路径泄漏。",
                    )
                )

            if re.search(r"DriverManager\.getConnection\s*\(", text):
                conn = re.search(r"\bConnection\s+(\w+)", text)
                name = conn.group(1) if conn else "connection"
                if name not in try_with and not _closed(method.body, name):
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=line_no,
                            snippet=unit.snippet(line_no),
                            message="JDBC Connection 可能未关闭，连接池会被耗尽。",
                            suggestion="使用 DataSource 并结合 try-with-resources 关闭 Connection/Statement/ResultSet。",
                            severity=Severity.CRITICAL,
                        )
                    )
            if re.search(r"\.(?:createStatement|prepareStatement|prepareCall|executeQuery)\s*\(", text):
                if "try (" not in method.body and not re.search(r"\.(?:close)\s*\(\s*\)", method.body):
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=line_no,
                            snippet=unit.snippet(line_no),
                            message="Statement / ResultSet 未在 try-with-resources 中管理。",
                            suggestion="把 Connection、Statement、ResultSet 全部放入 try-with-resources。",
                        )
                    )
        return _unique(findings)


def _try_with_resources(body: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"try\s*\((.*?)\)\s*\{", body, re.S):
        block = match.group(1)
        names.update(re.findall(r"\b([A-Z][A-Za-z0-9_]+)\b", block))
        names.update(re.findall(r"\b([a-zA-Z_][A-Za-z0-9_]*)\s*=", block))
    return names


def _in_try_with(text: str, try_with: set[str], var: str | None, rtype: str) -> bool:
    if "try (" in text or "try(" in text:
        return True
    if rtype in try_with:
        return True
    if var and var in try_with:
        return True
    return False


def _closed(body: str, name: str) -> bool:
    return bool(
        re.search(rf"{name}\.close\s*\(\s*\)", body)
        or re.search(rf"IOUtils\.closeQuietly\s*\(\s*{name}", body)
        or re.search(rf"closeQuietly\s*\(\s*{name}", body)
    )


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
