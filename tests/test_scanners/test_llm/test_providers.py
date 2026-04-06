"""Tests for LLM provider implementations."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import Settings


def _make_settings(**overrides) -> Settings:
    defaults = {
        "anthropic_api_key": "sk-test",
        "anthropic_model": "claude-test",
        "anthropic_timeout_seconds": 10,
        "openai_api_key": "sk-test",
        "openai_model": "gpt-test",
        "openai_timeout_seconds": 10,
        "ollama_enabled": True,
        "ollama_base_url": "http://localhost:11434",
        "ollama_model": "test-model",
        "ollama_timeout_seconds": 10,
        "llm_max_tokens": 1024,
        "custom_llm_base_url": "",
        "custom_llm_api_key": "",
    }
    defaults.update(overrides)
    return Settings(**defaults)


# ===== AnthropicProvider =====


class TestAnthropicProvider:
    def _make_provider(self, **kwargs):
        from app.scanners.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(_make_settings(**kwargs))

    def test_provider_name(self):
        p = self._make_provider()
        assert p.provider_name == "anthropic/claude-test"

    async def test_is_available_with_key(self):
        p = self._make_provider()
        assert await p.is_available() is True

    async def test_is_not_available_without_key(self):
        p = self._make_provider(anthropic_api_key="")
        assert await p.is_available() is False

    async def test_judge_extracts_tool_result(self):
        p = self._make_provider()

        tool_block = SimpleNamespace(
            type="tool_use",
            input={
                "verdict": "safe",
                "reasons": ["looks clean"],
                "confidence": 0.95,
                "suspicious_lines": [],
            },
        )
        mock_response = SimpleNamespace(
            content=[tool_block],
            usage=SimpleNamespace(input_tokens=100, output_tokens=50),
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test prompt")
        assert result.verdict == "safe"
        assert result.confidence == 0.95
        assert result.token_usage["prompt_tokens"] == 100

    async def test_judge_handles_no_tool_result(self):
        p = self._make_provider()

        text_block = SimpleNamespace(type="text", text="I think it's safe")
        mock_response = SimpleNamespace(
            content=[text_block],
            usage=SimpleNamespace(input_tokens=100, output_tokens=50),
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test prompt")
        assert result.verdict == "suspicious"
        assert result.confidence == 0.3

    async def test_judge_normalizes_invalid_verdict(self):
        p = self._make_provider()

        tool_block = SimpleNamespace(
            type="tool_use",
            input={"verdict": "UNKNOWN", "reasons": [], "confidence": 0.5, "suspicious_lines": []},
        )
        mock_response = SimpleNamespace(
            content=[tool_block],
            usage=SimpleNamespace(input_tokens=10, output_tokens=10),
        )

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test")
        assert result.verdict == "suspicious"

    async def test_judge_raises_on_api_error(self):
        p = self._make_provider()

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(side_effect=RuntimeError("API down"))
        p._client = mock_client

        with pytest.raises(RuntimeError, match="API down"):
            await p.judge("test")


# ===== OllamaProvider =====


class TestOllamaProvider:
    def _make_provider(self, **kwargs):
        from app.scanners.llm.ollama_provider import OllamaProvider

        return OllamaProvider(_make_settings(**kwargs))

    def test_provider_name(self):
        p = self._make_provider()
        assert p.provider_name == "ollama/test-model"

    async def test_is_available_disabled(self):
        p = self._make_provider(ollama_enabled=False)
        assert await p.is_available() is False

    async def test_is_available_checks_model(self):
        p = self._make_provider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "test-model:latest"}]}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            assert await p.is_available() is True

    async def test_is_available_model_not_found(self):
        p = self._make_provider()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"models": [{"name": "other-model:latest"}]}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            assert await p.is_available() is False

    async def test_is_available_connection_error(self):
        p = self._make_provider()
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
            assert await p.is_available() is False

    async def test_judge_parses_valid_json(self):
        p = self._make_provider()
        response_data = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "verdict": "malicious",
                                "reasons": ["eval usage"],
                                "confidence": 0.9,
                                "suspicious_lines": [],
                            }
                        )
                    }
                }
            ],
            "usage": {"prompt_tokens": 50, "completion_tokens": 30},
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status = MagicMock()

        p._client = AsyncMock()
        p._client.post = AsyncMock(return_value=mock_resp)

        result = await p.judge("test prompt")
        assert result.verdict == "malicious"
        assert result.confidence == 0.9

    async def test_judge_handles_invalid_json(self):
        p = self._make_provider()
        response_data = {
            "choices": [{"message": {"content": "not json at all"}}],
            "usage": {},
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.raise_for_status = MagicMock()

        p._client = AsyncMock()
        p._client.post = AsyncMock(return_value=mock_resp)

        result = await p.judge("test prompt")
        assert result.verdict == "suspicious"
        assert result.confidence == 0.3

    async def test_judge_raises_on_http_error(self):
        p = self._make_provider()
        p._client = AsyncMock()
        p._client.post = AsyncMock(side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()))

        with pytest.raises(httpx.HTTPStatusError):
            await p.judge("test")


# ===== OpenAIProvider =====


class TestOpenAIProvider:
    def _make_provider(self, **kwargs):
        from app.scanners.llm.openai_provider import OpenAIProvider

        return OpenAIProvider(_make_settings(**kwargs))

    def test_provider_name(self):
        p = self._make_provider()
        assert p.provider_name == "openai/gpt-test"

    async def test_is_available_with_key(self):
        p = self._make_provider()
        assert await p.is_available() is True

    async def test_is_available_with_custom_url(self):
        p = self._make_provider(openai_api_key="", custom_llm_base_url="http://vllm:8000/v1")
        assert await p.is_available() is True

    async def test_is_not_available_without_key_or_url(self):
        p = self._make_provider(openai_api_key="", custom_llm_base_url="")
        assert await p.is_available() is False

    async def test_judge_parses_valid_response(self):
        p = self._make_provider()

        parsed_content = json.dumps(
            {
                "verdict": "safe",
                "reasons": ["no issues"],
                "confidence": 0.95,
                "suspicious_lines": [],
            }
        )
        mock_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=parsed_content))],
            usage=SimpleNamespace(prompt_tokens=80, completion_tokens=40),
        )

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test prompt")
        assert result.verdict == "safe"
        assert result.confidence == 0.95
        assert result.token_usage["prompt_tokens"] == 80

    async def test_judge_handles_invalid_json(self):
        p = self._make_provider()

        mock_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="not json"))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10),
        )

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test")
        assert result.verdict == "suspicious"
        assert result.confidence == 0.3

    async def test_judge_handles_none_usage(self):
        p = self._make_provider()

        parsed_content = json.dumps(
            {
                "verdict": "safe",
                "reasons": [],
                "confidence": 0.9,
                "suspicious_lines": [],
            }
        )
        mock_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=parsed_content))],
            usage=None,
        )

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test")
        assert result.token_usage["prompt_tokens"] == 0

    async def test_judge_normalizes_invalid_verdict(self):
        p = self._make_provider()

        parsed_content = json.dumps(
            {
                "verdict": "BENIGN",
                "reasons": [],
                "confidence": 0.8,
                "suspicious_lines": [],
            }
        )
        mock_response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=parsed_content))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10),
        )

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = await p.judge("test")
        assert result.verdict == "suspicious"

    async def test_judge_raises_on_api_error(self):
        p = self._make_provider()

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("API error"))
        p._client = mock_client

        with pytest.raises(RuntimeError, match="API error"):
            await p.judge("test")
