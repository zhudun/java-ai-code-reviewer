from __future__ import annotations

from pathlib import Path

from java_reviewer.config import ReviewConfig
from java_reviewer.llm.client import LlmClient, parse_json_array, resolve_settings
from java_reviewer.llm.heuristics import heuristic_review
from java_reviewer.llm.prompts import SYSTEM_PROMPT_EN, SYSTEM_PROMPT_ZH, user_prompt
from java_reviewer.models import Finding, Severity, SourceKind


class ContextualReviewer:
    """Stage-2 reviewer: real LLM when configured, local heuristics otherwise."""

    def __init__(self, config: ReviewConfig) -> None:
        self.config = config
        self.settings = None
        if config.llm.enabled:
            self.settings = resolve_settings(
                config.llm.provider,
                config.llm.model,
                config.llm.base_url,
                config.llm.timeout_seconds,
            )
        self.client = LlmClient(self.settings) if self.settings else None

    @property
    def llm_used(self) -> bool:
        return self.client is not None

    def review_file(self, path: Path, existing: list[Finding]) -> list[Finding]:
        source = path.read_text(encoding="utf-8", errors="replace")
        if len(source) > self.config.llm.max_chars_per_file:
            source = source[: self.config.llm.max_chars_per_file]
        if self.client is None:
            return heuristic_review(path, source)
        try:
            findings = self._llm_review(path, source, existing)
        except Exception:
            return heuristic_review(path, source)
        return _ground(path, source, findings)

    def _llm_review(self, path: Path, source: str, existing: list[Finding]) -> list[Finding]:
        language = self.config.language
        system = SYSTEM_PROMPT_ZH if language.startswith("zh") else SYSTEM_PROMPT_EN
        existing_lines = [
            f"- {item.rule_id} L{item.line}: {item.title}"
            for item in existing
            if item.file.endswith(path.name) or item.file == str(path)
        ]
        content = self.client.complete(system, user_prompt(str(path), source, existing_lines, language))
        findings: list[Finding] = []
        for raw in parse_json_array(content):
            try:
                severity = Severity(str(raw.get("severity", "MEDIUM")).upper())
            except ValueError:
                severity = Severity.MEDIUM
            line = int(raw.get("line") or 1)
            findings.append(
                Finding(
                    rule_id=str(raw.get("rule_id") or "llm.context"),
                    title=str(raw.get("title") or "上下文问题"),
                    message=str(raw.get("message") or ""),
                    suggestion=str(raw.get("suggestion") or ""),
                    severity=severity,
                    file=str(path),
                    line=max(1, line),
                    snippet=_snippet(source, line),
                    source=SourceKind.LLM,
                    confidence=float(raw.get("confidence") or 0.6),
                    category=str(raw.get("category") or "correctness"),
                )
            )
        return findings


def _ground(path: Path, source: str, findings: list[Finding]) -> list[Finding]:
    lines = source.splitlines()
    grounded: list[Finding] = []
    for item in findings:
        if item.line > len(lines) or item.line < 1:
            continue
        if not item.message or not item.suggestion:
            continue
        item.file = str(path)
        item.snippet = item.snippet or _snippet(source, item.line)
        grounded.append(item)
    return grounded


def _snippet(source: str, line: int, radius: int = 2) -> str:
    lines = source.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    rows = []
    for idx in range(start, end + 1):
        prefix = ">" if idx == line else " "
        rows.append(f"{prefix} {idx:>4} | {lines[idx - 1]}")
    return "\n".join(rows)
