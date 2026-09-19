from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx


@dataclass
class LlmSettings:
    provider: str
    model: str
    api_key: str
    base_url: str
    timeout: float


def resolve_settings(provider: str, model: str, base_url: str | None, timeout: float) -> LlmSettings | None:
    provider = (provider or "openai").lower()
    if provider in {"anthropic", "claude"}:
        key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        url = base_url or "https://api.anthropic.com/v1/messages"
        if not key:
            return None
        return LlmSettings(provider="anthropic", model=model, api_key=key, base_url=url, timeout=timeout)

    key = (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("LLM_API_KEY")
        or os.environ.get("JACR_API_KEY")
    )
    url = base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    if not key:
        return None
    return LlmSettings(provider="openai", model=model, api_key=key, base_url=url.rstrip("/"), timeout=timeout)


class LlmClient:
    def __init__(self, settings: LlmSettings) -> None:
        self.settings = settings

    def complete(self, system: str, user: str) -> str:
        if self.settings.provider == "anthropic":
            return self._anthropic(system, user)
        return self._openai(system, user)

    def _openai(self, system: str, user: str) -> str:
        payload = {
            "model": self.settings.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.settings.base_url}/chat/completions"
        with httpx.Client(timeout=self.settings.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
        return data["choices"][0]["message"]["content"]

    def _anthropic(self, system: str, user: str) -> str:
        payload = {
            "model": self.settings.model,
            "max_tokens": 2000,
            "temperature": 0.1,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key": self.settings.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=self.settings.timeout) as client:
            response = client.post(self.settings.base_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
        return "".join(part.get("text", "") for part in data.get("content", []) if part.get("type") == "text")


def parse_json_array(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.replace("json\n", "", 1)
    start = text.find("[")
    end = text.rfind("]")
    if start < 0 or end < 0:
        return []
    data = json.loads(text[start : end + 1])
    return data if isinstance(data, list) else []
