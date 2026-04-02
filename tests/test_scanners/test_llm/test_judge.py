"""Tests for LLM Judge router."""

from unittest.mock import AsyncMock, patch

from app.core.config import Settings
from app.scanners.llm.judge import LLMJudgeScanner
from app.scanners.llm.provider import JudgeResult
from app.schemas.package import PackageInfo


def _make_settings(**overrides) -> Settings:
    defaults = {
        "llm_enabled": True,
        "llm_strategy": "cloud_only",
        "ollama_enabled": False,
        "anthropic_api_key": "sk-test-key",
        "openai_api_key": "",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _make_package() -> PackageInfo:
    return PackageInfo(name="test-pkg", version="1.0.0", registry="npm")


def _mock_judge_result(verdict="safe", confidence=0.9) -> JudgeResult:
    return JudgeResult(
        verdict=verdict,
        reasons=["test reason"],
        confidence=confidence,
        provider_name="test/model",
        latency_ms=100,
    )


async def test_no_files_returns_pass():
    scanner = LLMJudgeScanner(_make_settings())
    result = await scanner.scan(_make_package(), [])
    assert result.verdict == "pass"
    assert result.scanner_name == "llm_judge"


async def test_cloud_only_calls_anthropic(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("console.log('hello');")

    scanner = LLMJudgeScanner(_make_settings(llm_strategy="cloud_only"))
    mock_result = _mock_judge_result("safe", 0.95)

    with patch.object(scanner._cloud_primary, "judge", new_callable=AsyncMock, return_value=mock_result):
        with patch.object(scanner._cloud_primary, "is_available", new_callable=AsyncMock, return_value=True):
            result = await scanner.scan(_make_package(), [f])

    assert result.verdict == "pass"
    assert result.confidence == 0.95


async def test_malicious_result_maps_to_fail(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("eval(process.env)")

    scanner = LLMJudgeScanner(_make_settings())
    mock_result = _mock_judge_result("malicious", 0.9)

    with patch.object(scanner._cloud_primary, "judge", new_callable=AsyncMock, return_value=mock_result):
        with patch.object(scanner._cloud_primary, "is_available", new_callable=AsyncMock, return_value=True):
            result = await scanner.scan(_make_package(), [f])

    assert result.verdict == "fail"


async def test_suspicious_result_maps_to_warn(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("require('http')")

    scanner = LLMJudgeScanner(_make_settings())
    mock_result = _mock_judge_result("suspicious", 0.6)

    with patch.object(scanner._cloud_primary, "judge", new_callable=AsyncMock, return_value=mock_result):
        with patch.object(scanner._cloud_primary, "is_available", new_callable=AsyncMock, return_value=True):
            result = await scanner.scan(_make_package(), [f])

    assert result.verdict == "warn"


async def test_all_providers_fail_returns_degraded(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("test")

    scanner = LLMJudgeScanner(_make_settings(anthropic_api_key="", openai_api_key=""))
    scanner._cloud_primary = None
    scanner._cloud_fallback = None
    scanner._local = None

    result = await scanner.scan(_make_package(), [f])
    assert result.verdict == "pass"  # degraded mode returns pass, not warn
    assert result.metadata.get("degraded") is True


async def test_local_first_escalates_on_low_confidence(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("suspicious code")

    scanner = LLMJudgeScanner(
        _make_settings(llm_strategy="local_first", ollama_enabled=True, anthropic_api_key="sk-test")
    )

    local_result = _mock_judge_result("suspicious", 0.5)
    cloud_result = _mock_judge_result("malicious", 0.95)

    mock_local = AsyncMock()
    mock_local.judge = AsyncMock(return_value=local_result)
    mock_local.is_available = AsyncMock(return_value=True)
    mock_local.provider_name = "ollama/test"
    scanner._local = mock_local

    mock_cloud = AsyncMock()
    mock_cloud.judge = AsyncMock(return_value=cloud_result)
    mock_cloud.is_available = AsyncMock(return_value=True)
    mock_cloud.provider_name = "anthropic/test"
    scanner._cloud_primary = mock_cloud

    result = await scanner.scan(_make_package(), [f])
    assert result.verdict == "fail"  # malicious maps to fail
    assert result.confidence == 0.95


async def test_local_first_uses_local_on_high_confidence(tmp_path):
    f = tmp_path / "setup.js"
    f.write_text("safe code")

    scanner = LLMJudgeScanner(
        _make_settings(llm_strategy="local_first", ollama_enabled=True, anthropic_api_key="sk-test")
    )

    local_result = _mock_judge_result("safe", 0.95)

    mock_local = AsyncMock()
    mock_local.judge = AsyncMock(return_value=local_result)
    mock_local.is_available = AsyncMock(return_value=True)
    mock_local.provider_name = "ollama/test"
    scanner._local = mock_local

    mock_cloud = AsyncMock()
    mock_cloud.judge = AsyncMock()  # Should not be called
    mock_cloud.is_available = AsyncMock(return_value=True)
    scanner._cloud_primary = mock_cloud

    result = await scanner.scan(_make_package(), [f])
    assert result.verdict == "pass"
    mock_cloud.judge.assert_not_called()
