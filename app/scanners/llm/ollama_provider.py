"""Ollama (local LLM) provider via OpenAI-compatible API."""

import json
import time

import httpx
from loguru import logger

from app.core.config import Settings
from app.scanners.llm.provider import JudgeResult


class OllamaProvider:
    """Local LLM via Ollama's OpenAI-compatible /v1/chat/completions endpoint."""

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.ollama_base_url.rstrip("/")
        self._model = settings.ollama_model
        self._timeout = settings.ollama_timeout_seconds
        self._enabled = settings.ollama_enabled
        self._client = httpx.AsyncClient(timeout=self._timeout)

    @property
    def provider_name(self) -> str:
        return f"ollama/{self._model}"

    async def is_available(self) -> bool:
        if not self._enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as check_client:
                resp = await check_client.get(f"{self._base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                models = resp.json().get("models", [])
                return any(m.get("name", "").startswith(self._model.split(":")[0]) for m in models)
        except Exception:
            return False

    async def judge(self, prompt: str) -> JudgeResult:
        start = time.monotonic()
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "format": {"type": "json_object"},
            "stream": False,
        }

        try:
            resp = await self._client.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.error("Ollama request failed: {err}", err=str(e))
            raise

        elapsed = int((time.monotonic() - start) * 1000)
        data = resp.json()
        content = data["choices"][0]["message"]["content"]

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Ollama returned invalid JSON, treating as suspicious")
            return JudgeResult(
                verdict="suspicious",
                reasons=["LLM output was not valid JSON"],
                confidence=0.3,
                provider_name=self.provider_name,
                latency_ms=elapsed,
            )

        usage = data.get("usage", {})
        raw_verdict = str(parsed.get("verdict", "suspicious")).strip().lower()
        valid_verdicts = {"safe", "suspicious", "malicious"}
        verdict = raw_verdict if raw_verdict in valid_verdicts else "suspicious"
        return JudgeResult(
            verdict=verdict,
            reasons=parsed.get("reasons", []),
            confidence=parsed.get("confidence", 0.5),
            suspicious_lines=parsed.get("suspicious_lines", []),
            provider_name=self.provider_name,
            latency_ms=elapsed,
            token_usage={
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
            },
        )
