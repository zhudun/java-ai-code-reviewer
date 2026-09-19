from __future__ import annotations

import re

from java_reviewer.analyze.source import JavaClass, JavaCompilationUnit, JavaMethod
from java_reviewer.config import ReviewConfig
from java_reviewer.models import Finding, Severity
from java_reviewer.rules.base import Rule

WRITE_HINTS = (
    r"\.(?:save|saveAll|update|delete|remove|persist|merge|flush)\s*\(",
    r"(?:insert|update|delete)\s+",
    r"jdbcTemplate\.(?:update|batchUpdate)",
)


class TransactionBoundaryRule(Rule):
    rule_id = "java.transaction"
    title = "事务边界问题"
    category = "correctness"
    default_severity = Severity.HIGH
    cwe = "CWE-662"

    def check_java(self, unit: JavaCompilationUnit, config: ReviewConfig) -> list[Finding]:
        findings: list[Finding] = []
        for cls in unit.classes:
            transactional_names = {
                method.name for method in cls.methods if method.has_annotation("Transactional")
            }
            class_tx = cls.has_annotation("Transactional")
            if cls.has_annotation("RestController") or cls.has_annotation("Controller"):
                if class_tx or any(m.has_annotation("Transactional") for m in cls.methods):
                    line = cls.start_line
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=line,
                            snippet=unit.snippet(line),
                            severity=Severity.MEDIUM,
                            message=f"Controller `{cls.name}` 上声明了 @Transactional，事务边界放错了层。",
                            suggestion="把事务放到 Service 层；Controller 只负责入参校验与编排。",
                        )
                    )
            for method in cls.methods:
                findings.extend(self._method(unit, cls, method, transactional_names, class_tx))
        return findings

    def _method(
        self,
        unit: JavaCompilationUnit,
        cls: JavaClass,
        method: JavaMethod,
        transactional_names: set[str],
        class_tx: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        has_tx = method.has_annotation("Transactional") or class_tx
        if method.has_annotation("Transactional") and not method.is_public:
            findings.append(
                self.finding(
                    file=unit.path,
                    line=method.signature_line,
                    snippet=unit.snippet(method.signature_line),
                    message=(
                        f"`{cls.name}.{method.name}` 是非 public 方法上的 @Transactional，"
                        "Spring 代理默认不会生效。"
                    ),
                    suggestion="改为 public，并通过另一个 Bean 调用；不要用 this.xxx() 自调用。",
                    severity=Severity.CRITICAL,
                )
            )

        if has_tx:
            if re.search(r"catch\s*\([^)]*Exception[^)]*\)\s*\{", method.body):
                if not re.search(r"throw\b", method.body):
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=method.signature_line,
                            snippet=unit.snippet(method.signature_line),
                            message=(
                                f"`{method.name}` 在事务方法里吞掉 Exception，"
                                "默认只会回滚 RuntimeException。"
                            ),
                            suggestion=(
                                "重新抛出异常，或设置 @Transactional(rollbackFor = Exception.class)，"
                                "并避免在事务内吞异常。"
                            ),
                        )
                    )
            anno = method.annotation_text("Transactional") or ""
            if _has_write(method.body) and "readOnly" in anno and "true" in anno:
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=method.signature_line,
                        snippet=unit.snippet(method.signature_line),
                        message=f"`{method.name}` 标记 readOnly=true 却包含写库操作。",
                        suggestion="写操作请去掉 readOnly，或拆成只读查询方法与写方法。",
                    )
                )

        # self-invocation of transactional methods
        for name in transactional_names:
            if name == method.name:
                continue
            if re.search(rf"(?:this\.)?{name}\s*\(", method.body):
                if not method.has_annotation("Transactional") and not class_tx:
                    findings.append(
                        self.finding(
                            file=unit.path,
                            line=method.signature_line,
                            snippet=unit.snippet(method.signature_line),
                            message=(
                                f"`{method.name}` 以 this 调用同类 `{name}()`，"
                                "Spring AOP 代理不会织入事务。"
                            ),
                            suggestion="抽出到另一个 Service Bean，或使用 ApplicationContext/AopContext 取代理。",
                            severity=Severity.HIGH,
                        )
                    )

        if not has_tx and _has_write(method.body) and cls.has_annotation("Service"):
            if method.is_public and not method.has_annotation("Transactional"):
                findings.append(
                    self.finding(
                        file=unit.path,
                        line=method.signature_line,
                        snippet=unit.snippet(method.signature_line),
                        severity=Severity.MEDIUM,
                        message=f"Service 方法 `{method.name}` 包含写库操作但未见事务边界。",
                        suggestion="为涉及多步写库的方法补充 @Transactional，并明确 rollbackFor。",
                    )
                )
        return findings


def _has_write(body: str) -> bool:
    return any(re.search(pattern, body, re.I) for pattern in WRITE_HINTS)
