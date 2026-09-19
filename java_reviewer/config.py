from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class RuleConfig(BaseModel):
    enabled: bool = True
    severity: str | None = None


class LlmConfig(BaseModel):
    enabled: bool = True
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    timeout_seconds: float = 45.0
    max_files: int = 12
    max_chars_per_file: int = 8000


class ReviewConfig(BaseModel):
    include: list[str] = Field(default_factory=lambda: ["**/*.java", "**/*mapper*.xml", "**/*dao*.xml"])
    exclude: list[str] = Field(
        default_factory=lambda: [
            "**/target/**",
            "**/build/**",
            "**/.git/**",
            "**/generated/**",
            "**/.idea/**",
        ]
    )
    fail_on: str = "HIGH"
    language: str = "zh"
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    llm: LlmConfig = Field(default_factory=LlmConfig)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ReviewConfig":
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    def rule_enabled(self, rule_id: str) -> bool:
        family = rule_id.split(".")[0]
        for key in (rule_id, family):
            item = self.rules.get(key)
            if item is not None:
                return item.enabled
        return True

    def override_severity(self, rule_id: str) -> str | None:
        item = self.rules.get(rule_id)
        if item and item.severity:
            return item.severity
        family = self.rules.get(rule_id.split(".")[0])
        if family and family.severity:
            return family.severity
        return None

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()
