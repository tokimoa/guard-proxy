"""Anthropic Claude API provider using tool_use for structured output."""

import time

from loguru import logger

from app.core.config import Settings
from app.scanners.llm.provider import JUDGE_RESULT_SCHEMA, JudgeResult


class AnthropicProvider:
    """Claude API provider using tool_use for structured JSON output."""

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.anthropic_api_key
        self._model = settings.anthropic_model
        self._timeout = settings.anthropic_timeout_seconds
        self._max_tokens = settings.llm_max_tokens

    @property
    def provider_name(self) -> str:
        return f"anthropic/{self._model}"

    async def is_available(self) -> bool:
        return bool(self._api_key)

    async def judge(self, prompt: str) -> JudgeResult:
        import anthropic

        start = time.monotonic()

        client = anthropic.AsyncAnthropic(
            api_key=self._api_key,
            timeout=self._timeout,
        )

        tool_def = {
            "name": "report_scan_result",
            "description": "Report the security scan result for the analyzed code.",
            "input_schema": JUDGE_RESULT_SCHEMA,
        }

        try:
            response = await client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                tools=[tool_def],
                tool_choice={"type": "tool", "name": "report_scan_result"},
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:
            logger.error("Anthropic API error: {err}", err=str(e))
            raise

        elapsed = int((time.monotonic() - start) * 1000)

        # Extract tool_use result
        tool_result = None
        for block in response.content:
            if block.type == "tool_use":
                tool_result = block.input
                break

        if not tool_result:
            logger.warning("Anthropic did not return tool_use result")
            return JudgeResult(
                verdict="suspicious",
                reasons=["No structured output from Anthropic"],
                confidence=0.3,
                provider_name=self.provider_name,
                latency_ms=elapsed,
            )

        return JudgeResult(
            verdict=tool_result.get("verdict", "suspicious"),
            reasons=tool_result.get("reasons", []),
            confidence=tool_result.get("confidence", 0.5),
            suspicious_lines=tool_result.get("suspicious_lines", []),
            provider_name=self.provider_name,
            latency_ms=elapsed,
            token_usage={
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
            },
        )
