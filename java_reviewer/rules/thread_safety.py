from __future__ import annotations

import re

from java_reviewer.analyze.source import JavaClass, JavaCompilationUnit, JavaField
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule

UNSAFE_COLLECTIONS = (
    "HashMap",
    "HashSet",
    "ArrayList",
    "LinkedList",
    "TreeMap",
    "TreeSet",
    "SimpleDateFormat",
    "Calendar",
    "DecimalFormat",
)


class ThreadSafetyRule(Rule):
    rule_id = "java.thread-safety"
    title = "线程安全问题"
    category = "concurrency"
    default_severity = Severity.HIGH
    cwe = "CWE-362"

    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        for cls in unit.classes:
            findings.extend(self._fields(unit, cls))
            findings.extend(self._double_checked(unit, cls))
            findings.extend(self._check_then_act(unit, cls))
        return findings

    def _fields(self, unit: JavaCompilationUnit, cls: JavaClass) -> list[Finding]:
        findings: list[Finding] = []
        singleton = cls.is_spring_singleton() or "static" in cls.modifiers
        for field in cls.fields:
            raw_type = field.type
            if "SimpleDateFormat" in raw_type:
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=field.line,
                        snippet=unit.snippet(field.line),
                        severity=Severity.CRITICAL,
                        message=f"字段 `{field.name}` 使用线程不安全的 SimpleDateFormat。",
                        suggestion="改用 DateTimeFormatter（不可变）或在方法内创建 / ThreadLocal。",
                    )
                )
                continue
            if "Calendar" in raw_type and "static" in field.modifiers:
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=field.line,
                        snippet=unit.snippet(field.line),
                        message=f"静态 Calendar 字段 `{field.name}` 会被多线程共享修改。",
                        suggestion="使用 java.time API，或每次调用 Instant/LocalDateTime 新建对象。",
                    )
                )
            if not singleton and "static" not in field.modifiers:
                continue
            if _is_safe_collection(field):
                continue
            combined = f"{raw_type} {field.initializer}"
            if any(item in combined for item in ("HashMap", "ArrayList", "HashSet", "LinkedList")):
                if "final" in field.modifiers and _immutable_init(field):
                    continue
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=field.line,
                        snippet=unit.snippet(field.line),
                        message=(
                            f"{'Spring 单例 Bean' if cls.is_spring_singleton() else '共享对象'} "
                            f"中的 `{field.name}` ({raw_type}) 不是线程安全集合。"
                        ),
                        suggestion="改为 ConcurrentHashMap / CopyOnWriteArrayList，或加锁后访问。",
                    )
                )
        return findings

    def _double_checked(self, unit: JavaCompilationUnit, cls: JavaClass) -> list[Finding]:
        findings: list[Finding] = []
        text = cls.raw
        if not re.search(r"if\s*\(\s*\w+\s*==\s*null\s*\)\s*\{[^}]*synchronized", text, re.S):
            return findings
        if re.search(r"if\s*\(\s*\w+\s*==\s*null\s*\).*synchronized.*if\s*\(\s*\w+\s*==\s*null\s*\)", text, re.S):
            volatile_fields = {f.name for f in cls.fields if "volatile" in f.modifiers}
            assigned = re.findall(r"if\s*\(\s*(\w+)\s*==\s*null\s*\)", text)
            for name in assigned:
                if name not in volatile_fields:
                    line = _line_of(unit, rf"{name}\s*==\s*null")
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=line,
                            snippet=unit.snippet(line),
                            severity=Severity.CRITICAL,
                            message=f"双重检查锁定使用了非 volatile 字段 `{name}`，可能发布未初始化对象。",
                            suggestion="把字段声明为 volatile，或改用静态内部类 / enum 单例。",
                        )
                    )
                    break
        return findings

    def _check_then_act(self, unit: JavaCompilationUnit, cls: JavaClass) -> list[Finding]:
        findings: list[Finding] = []
        shared = {
            f.name
            for f in cls.fields
            if "static" in f.modifiers or cls.is_spring_singleton()
        }
        if not shared:
            return findings
        for method in cls.methods:
            if "synchronized" in method.modifiers:
                continue
            body = method.body
            for name in shared:
                if re.search(rf"if\s*\(\s*!{name}\.containsKey", body) and re.search(
                    rf"{name}\.put\s*\(", body
                ):
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=method.signature_line,
                            snippet=unit.snippet(method.signature_line),
                            message=f"方法 `{method.name}` 对共享 Map `{name}` 做了无锁的 check-then-act。",
                            suggestion="使用 ConcurrentHashMap.computeIfAbsent，或把检查与写入放进同一把锁。",
                        )
                    )
                if re.search(rf"{name}\s*\+\+", body) or re.search(rf"{name}\s*=\s*{name}\s*\+", body):
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=method.signature_line,
                            snippet=unit.snippet(method.signature_line),
                            message=f"共享计数器 `{name}` 的复合更新不是原子操作。",
                            suggestion="使用 AtomicInteger / LongAdder，或对更新加锁。",
                        )
                    )
        return findings


def _is_safe_collection(field: JavaField) -> bool:
    text = f"{field.type} {field.initializer}"
    return any(
        token in text
        for token in (
            "ConcurrentHashMap",
            "ConcurrentMap",
            "CopyOnWriteArrayList",
            "CopyOnWriteArraySet",
            "Collections.synchronized",
            "ConcurrentLinkedQueue",
            "AtomicInteger",
            "AtomicLong",
            "AtomicReference",
        )
    )


def _immutable_init(field: JavaField) -> bool:
    init = field.initializer
    return bool(init) and (
        "Map.of" in init or "List.of" in init or "Set.of" in init or "Collections.empty" in init
    )


def _line_of(unit: JavaCompilationUnit, pattern: str) -> int:
    regex = re.compile(pattern)
    for idx, line in enumerate(unit.clean_lines, start=1):
        if regex.search(line):
            return idx
    return 1
