"""Multi-provider LLM client for SOC analysis."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from aegis.config import get_settings


class LLMClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def provider(self) -> str:
        if self.settings.aegis_llm_provider == "anthropic" and self.settings.anthropic_api_key:
            return "anthropic"
        if self.settings.aegis_llm_provider == "ollama":
            return "ollama"
        if self.settings.openai_api_key:
            return "openai"
        if self.settings.anthropic_api_key:
            return "anthropic"
        return "local"

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        json_mode: bool = True,
    ) -> dict[str, Any]:
        provider = self.provider
        if provider == "openai":
            return self._openai(system_prompt, user_prompt, json_mode)
        if provider == "anthropic":
            return self._anthropic(system_prompt, user_prompt, json_mode)
        if provider == "ollama":
            return self._ollama(system_prompt, user_prompt, json_mode)
        return self._local_fallback(user_prompt)

    def _openai(self, system: str, user: str, json_mode: bool) -> dict[str, Any]:
        from openai import OpenAI

        client = OpenAI(api_key=self.settings.openai_api_key)
        kwargs: dict[str, Any] = {
            "model": self.settings.aegis_llm_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content or "{}"
        return self._parse_json(content)

    def _anthropic(self, system: str, user: str, json_mode: bool) -> dict[str, Any]:
        from anthropic import Anthropic

        client = Anthropic(api_key=self.settings.anthropic_api_key)
        prompt = user
        if json_mode:
            prompt += "\n\nRespond with valid JSON only."

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text
        return self._parse_json(content)

    def _ollama(self, system: str, user: str, json_mode: bool) -> dict[str, Any]:
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(
                f"{self.settings.ollama_base_url}/api/chat",
                json={
                    "model": self.settings.aegis_llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "format": "json" if json_mode else None,
                },
            )
            content = resp.json().get("message", {}).get("content", "{}")
            return self._parse_json(content)

    def _local_fallback(self, user_prompt: str) -> dict[str, Any]:
        text = user_prompt.lower()
        if "udp" in text or "flood" in text:
            attack = "UDP Flood / DoS"
            risk = "High"
        elif "scan" in text:
            attack = "Port Scanning / Reconnaissance"
            risk = "Medium"
        elif "lateral" in text or "internal" in text:
            attack = "Lateral Movement"
            risk = "High"
        else:
            attack = "Suspicious Network Activity"
            risk = "Medium"

        return {
            "attack_type": attack,
            "reason": "Rule-based analysis (no LLM API key configured).",
            "risk": risk,
            "action": "Investigate source host, enrich IOCs, and correlate with SIEM events.",
            "mitre_techniques": ["T1071"],
        }

    def _parse_json(self, content: str) -> dict[str, Any]:
        content = content.strip()
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                return json.loads(match.group())
            return {
                "attack_type": "Analysis Error",
                "reason": content[:500],
                "risk": "Medium",
                "action": "Manual analyst review required.",
                "mitre_techniques": [],
            }


_llm: LLMClient | None = None


def get_llm() -> LLMClient:
    global _llm
    if _llm is None:
        _llm = LLMClient()
    return _llm