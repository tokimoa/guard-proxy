"""OpenAI GPT provider using response_format for structured output."""

import json
import time

from loguru import logger

from app.core.config import Settings
from app.scanners.llm.provider import JUDGE_RESULT_SCHEMA, JudgeResult


class OpenAIProvider:
    """OpenAI GPT provider with JSON schema structured output."""

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.openai_api_key
        self._model = settings.openai_model
        self._timeout = settings.openai_timeout_seconds
        self._max_tokens = settings.llm_max_tokens
        # Support custom OpenAI-compatible endpoints (vLLM etc.)
        self._base_url = settings.custom_llm_base_url or None
        self._client = None  # Lazy init

    @property
    def provider_name(self) -> str:
        return f"openai/{self._model}"

    async def is_available(self) -> bool:
        return bool(self._api_key or self._base_url)

    def _get_client(self):  # noqa: ANN202
        if self._client is None:
            import openai

            client_kwargs = {"timeout": self._timeout}
            if self._api_key:
                client_kwargs["api_key"] = self._api_key
            if self._base_url:
                client_kwargs["base_url"] = self._base_url
            self._client = openai.AsyncOpenAI(**client_kwargs)
        return self._client

    async def judge(self, prompt: str) -> JudgeResult:
        start = time.monotonic()
        client = self._get_client()

        try:
            response = await client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=self._max_tokens,
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "scan_result",
                        "schema": JUDGE_RESULT_SCHEMA,
                        "strict": True,
                    },
                },
            )
        except Exception as e:
            logger.error("OpenAI API error: {err}", err=str(e))
            raise

        elapsed = int((time.monotonic() - start) * 1000)
        content = response.choices[0].message.content or "{}"

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("OpenAI returned invalid JSON")
            return JudgeResult(
                verdict="suspicious",
                reasons=["Invalid JSON from OpenAI"],
                confidence=0.3,
                provider_name=self.provider_name,
                latency_ms=elapsed,
            )

        usage = response.usage
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
                "prompt_tokens": usage.prompt_tokens if usage else 0,
                "completion_tokens": usage.completion_tokens if usage else 0,
            },
        )
