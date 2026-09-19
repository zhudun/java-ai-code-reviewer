from __future__ import annotations

import re

from java_reviewer.analyze.source import JavaCompilationUnit, JavaMethod
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule

_NULLABLE_CALLS = (
    r"findById|findOne|getById|orElse\(null\)|map\.get|getParameter|getHeader|"
    r"getAttribute|request\.get|optional\.get|orElseGet"
)
_UNBOX_TYPES = r"Integer|Long|Double|Float|Boolean|Short|Byte"


class NullPointerRule(Rule):
    rule_id = "java.npe"
    title = "空指针 / NPE 风险"
    category = "reliability"
    default_severity = Severity.HIGH
    cwe = "CWE-476"

    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        for cls in unit.classes:
            for method in cls.methods:
                findings.extend(self._scan_method(unit, method))
        return findings

    def _scan_method(self, unit: JavaCompilationUnit, method: JavaMethod) -> list[Finding]:
        findings: list[Finding] = []
        body = method.body
        lines = _numbered_lines(unit, method)

        for line_no, text in lines:
            stripped = text.strip()

            if re.search(r"\.orElse\s*\(\s*null\s*\)", stripped):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message="Optional.orElse(null) 会把空值重新引入调用链，后续解引用很容易 NPE。",
                        suggestion="改用 orElseThrow()、orElseGet()，或在使用前用 ifPresent / map 处理缺失值。",
                    )
                )

            if re.search(r"\bOptional\s*<[^>]+>\s+\w+", stripped) is None:
                optional_get = re.search(r"(\w+)\.get\s*\(\s*\)", stripped)
                if optional_get and _looks_like_optional(body, optional_get.group(1), unit, method):
                    if not _guarded_by_is_present(body, optional_get.group(1)):
                        findings.append(
                            self.finding(
                                file=unit.path,
                                line=line_no,
                                snippet=unit.snippet(line_no),
                                message=f"直接调用 `{optional_get.group(1)}.get()`，未确认 Optional 有值。",
                                suggestion="先 isPresent()/ifPresent()，或改用 orElseThrow() / orElseGet()。",
                            )
                        )

            if re.search(r"\.(?:get|findById|findOne)\s*\([^;]*\)\s*\.\s*\w+\s*\(", stripped):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message="对可能返回 null 的查询/Map.get 结果直接链式调用，存在 NPE 风险。",
                        suggestion="拆开调用并用 Objects.requireNonNull、Optional 或显式空判断保护。",
                    )
                )

            equals = re.search(r"(?<![A-Za-z0-9_\"'])([A-Za-z_]\w*(?:\.\w+\(\))*)\.equals\s*\(", stripped)
            if equals:
                left = equals.group(1)
                if not left.startswith('"') and left not in {"Objects"}:
                    if not _null_checked(body, left.split(".")[0]):
                        findings.append(
                            self.finding(
                                file=unit.path,
                                line=line_no,
                                snippet=unit.snippet(line_no),
                                severity=Severity.MEDIUM,
                                message=f"`{left}.equals(...)` 在左侧为 null 时会抛出 NPE。",
                                suggestion='把常量放左边，例如 `"admin".equals(name)`，或使用 Objects.equals(a, b)。',
                            )
                        )

            unbox = re.search(
                rf"(?:int|long|double|float|boolean|short|byte)\s+\w+\s*=\s*(\w+)\s*;",
                stripped,
            )
            if unbox and re.search(rf"\b({_UNBOX_TYPES})\b", method.body):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message=f"包装类型 `{unbox.group(1)}` 自动拆箱，值为 null 时会 NPE。",
                        suggestion="拆箱前判空，或使用 intValue() 的安全封装 / OptionalInt。",
                    )
                )

            if re.search(rf"({_NULLABLE_CALLS}).*\.toString\s*\(", stripped, re.I):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=line_no,
                        snippet=unit.snippet(line_no),
                        message="对可能为 null 的对象调用 toString()。",
                        suggestion="使用 String.valueOf(...) 或 Objects.toString(value, defaultValue)。",
                    )
                )

        findings.extend(self._null_then_deref(unit, method, lines))
        return _dedupe(findings)

    def _null_then_deref(
        self,
        unit: JavaCompilationUnit,
        method: JavaMethod,
        lines: list[tuple[int, str]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        assigned_null: dict[str, int] = {}
        for line_no, text in lines:
            match = re.search(rf"\b({_ident()})\s*=\s*null\b", text)
            if match:
                assigned_null[match.group(1)] = line_no
                continue
            for name, at in list(assigned_null.items()):
                if re.search(rf"\b{name}\s*=\s*(?!null\b)", text):
                    assigned_null.pop(name, None)
                    continue
                if re.search(rf"\b{name}\s*\.", text) and "if" not in text:
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=line_no,
                            snippet=unit.snippet(line_no),
                            message=f"变量 `{name}` 在第 {at} 行被赋值为 null 后仍被解引用。",
                            suggestion="删除无效赋值，或在使用前重新赋值并做空判断。",
                        )
                    )
        return findings


def _ident() -> str:
    return r"[A-Za-z_][A-Za-z0-9_]*"


def _numbered_lines(unit: JavaCompilationUnit, method: JavaMethod) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for line_no in range(method.start_line, method.end_line + 1):
        if 1 <= line_no <= len(unit.clean_lines):
            rows.append((line_no, unit.clean_lines[line_no - 1]))
    return rows


def _looks_like_optional(body: str, name: str, unit: JavaCompilationUnit, method: JavaMethod) -> bool:
    if re.search(rf"Optional\s*<[^>]+>\s+{name}\b", body):
        return True
    if re.search(rf"Optional\s*<[^>]+>\s+{name}\b", method.raw):
        return True
    if name.lower() in {"optional", "opt", "maybe"}:
        return True
    if any("Optional" in imported for imported in unit.imports) and name.endswith("Opt"):
        return True
    # Optional from ofNullable / findBy*
    if re.search(rf"\b{name}\s*=\s*.*(?:Optional\.|findBy|findOne)", body):
        return True
    return bool(re.search(rf"Optional<{_ident()}>\s+{name}\b", method.raw))


def _guarded_by_is_present(body: str, name: str) -> bool:
    return bool(
        re.search(rf"{name}\.isPresent\s*\(\s*\)", body)
        or re.search(rf"{name}\.isEmpty\s*\(\s*\)", body)
        or re.search(rf"ifPresent\s*\(", body)
    )


def _null_checked(body: str, name: str) -> bool:
    return bool(
        re.search(rf"{name}\s*!=\s*null", body)
        or re.search(rf"Objects\.requireNonNull\s*\(\s*{name}", body)
        or re.search(rf"Objects\.equals\s*\(", body)
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for item in findings:
        key = item.fingerprint()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
