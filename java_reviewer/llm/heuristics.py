from __future__ import annotations

import re
from pathlib import Path

from java_reviewer.analyze.source import JavaCompilationUnit, parse_java
from java_reviewer.models import Finding, Severity, SourceKind

_SECRET = re.compile(
    r"""(?i)(password|secret|api[_-]?key|access[_-]?key|token)\s*=\s*["'][^"']{6,}["']"""
)
_WEAK_RANDOM = re.compile(r"\bnew\s+Random\s*\(")
_FASTJSON = re.compile(r"JSON\.parse(?:Object|Array)?\s*\(")
_PATH_TRAVERSAL = re.compile(r"new\s+File\s*\(\s*[^)]*(?:request|param|name|path|filename)", re.I)
_EMPTY_CATCH = re.compile(r"catch\s*\([^)]+\)\s*\{\s*(?://[^\n]*)?\s*\}", re.S)
_SSRF = re.compile(r"new\s+URL\s*\(\s*([^)]+)\)|RestTemplate.*\.(?:getForObject|exchange)\s*\(\s*(\w+)")
_AUTH_ANN = ("PreAuthorize", "Secured", "RolesAllowed", "RequiresPermissions")


def heuristic_review(path: Path, source: str) -> list[Finding]:
    if path.suffix != ".java":
        return []
    unit = parse_java(str(path), source)
    findings: list[Finding] = []
    findings.extend(_secrets(unit))
    findings.extend(_random(unit))
    findings.extend(_fastjson(unit))
    findings.extend(_path(unit))
    findings.extend(_empty_catch(unit))
    findings.extend(_auth(unit))
    findings.extend(_ssrf(unit))
    return findings


def _item(
    unit: JavaCompilationUnit,
    line: int,
    rule_id: str,
    title: str,
    message: str,
    suggestion: str,
    severity: Severity,
    category: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        message=message,
        suggestion=suggestion,
        severity=severity,
        file=unit.path,
        line=line,
        snippet=unit.snippet(line),
        source=SourceKind.HEURISTIC,
        confidence=0.72,
        category=category,
    )


def _secrets(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for idx, line in enumerate(unit.clean_lines, start=1):
        if _SECRET.search(line) and "passwordEncoder" not in line:
            findings.append(
                _item(
                    unit,
                    idx,
                    "llm.hardcoded-secret",
                    "硬编码密钥",
                    "源码中出现疑似硬编码口令或密钥，一旦入库即泄露。",
                    "移到环境变量 / 密钥管理服务，并轮换已暴露的凭据。",
                    Severity.CRITICAL,
                    "security",
                )
            )
    return findings


def _random(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    securityish = any(
        token in unit.source.lower()
        for token in ("token", "reset", "otp", "session", "csrf", "jwt", "captcha")
    )
    if not securityish:
        return findings
    for idx, line in enumerate(unit.clean_lines, start=1):
        if _WEAK_RANDOM.search(line):
            findings.append(
                _item(
                    unit,
                    idx,
                    "llm.weak-random",
                    "安全场景使用弱随机数",
                    "java.util.Random 可预测，不能用于令牌 / 验证码 / 会话。",
                    "改用 SecureRandom 或 java.security.SecureRandom。",
                    Severity.HIGH,
                    "security",
                )
            )
    return findings


def _fastjson(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for idx, line in enumerate(unit.clean_lines, start=1):
        if _FASTJSON.search(line) or "XMLDecoder" in line:
            findings.append(
                _item(
                    unit,
                    idx,
                    "llm.insecure-deserialize",
                    "不安全反序列化",
                    "Fastjson / XMLDecoder 解析不可信输入存在历史 RCE 风险。",
                    "对不可信数据使用 Jackson 并关闭默认类型，或做白名单反序列化。",
                    Severity.HIGH,
                    "security",
                )
            )
    return findings


def _path(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for idx, line in enumerate(unit.clean_lines, start=1):
        if _PATH_TRAVERSAL.search(line):
            findings.append(
                _item(
                    unit,
                    idx,
                    "llm.path-traversal",
                    "路径穿越风险",
                    "用请求参数直接拼接文件系统路径，可能读出/覆盖任意文件。",
                    "规范化路径后校验仍落在允许目录内，并拒绝 `..`。",
                    Severity.HIGH,
                    "security",
                )
            )
    return findings


def _empty_catch(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for match in _EMPTY_CATCH.finditer(unit.clean):
        line = unit.clean[: match.start()].count("\n") + 1
        findings.append(
            _item(
                unit,
                line,
                "llm.empty-catch",
                "空 catch 吞掉异常",
                "捕获后不记录也不抛出，故障会被静默，事务/资源状态难排查。",
                "至少记录日志；需要回滚时重新抛出，或转为业务异常。",
                Severity.MEDIUM,
                "reliability",
            )
        )
    return findings


def _auth(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for cls in unit.classes:
        if not (cls.has_annotation("RestController") or cls.has_annotation("Controller")):
            continue
        class_protected = any(cls.has_annotation(name) for name in _AUTH_ANN)
        for method in cls.methods:
            if not method.is_public:
                continue
            mapping = any(
                method.has_annotation(name)
                for name in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping")
            )
            if not mapping:
                continue
            protected = class_protected or any(method.has_annotation(name) for name in _AUTH_ANN)
            if not protected:
                findings.append(
                    _item(
                        unit,
                        method.signature_line,
                        "llm.missing-authz",
                        "接口缺少授权注解",
                        f"`{cls.name}.{method.name}` 是 Web 接口，未见 PreAuthorize/Secured 等授权控制。",
                        "在方法或类上补充授权注解，并在服务层再次校验资源归属。",
                        Severity.HIGH,
                        "security",
                    )
                )
    return findings


def _ssrf(unit: JavaCompilationUnit) -> list[Finding]:
    findings = []
    for idx, line in enumerate(unit.clean_lines, start=1):
        if _SSRF.search(line) and any(token in line for token in ("request", "param", "url", "uri", "host")):
            findings.append(
                _item(
                    unit,
                    idx,
                    "llm.ssrf",
                    "服务端请求伪造 (SSRF)",
                    "用外部传入的 URL 直接发请求，可能打到内网或云元数据。",
                    "对协议/主机做白名单，禁止 127.0.0.1、169.254.169.254 和 file://。",
                    Severity.HIGH,
                    "security",
                )
            )
    return findings
