"""Tests for TieredScanPipeline — 4 decision paths."""

from unittest.mock import AsyncMock

from app.scanners.base import TieredScanPipeline
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


def _pkg() -> PackageInfo:
    return PackageInfo(name="test", version="1.0.0", registry="npm")


def _result(name: str, verdict: str, confidence: float = 0.9) -> ScanResult:
    return ScanResult(scanner_name=name, verdict=verdict, confidence=confidence, details="test")


def _mock_scanner(result: ScanResult) -> AsyncMock:
    scanner = AsyncMock()
    scanner.scan = AsyncMock(return_value=result)
    return scanner


async def test_case1_critical_hit_skips_slow():
    """Case 1: IOC/critical hit — skip LLM, block immediately."""
    fast = [_mock_scanner(_result("ioc_check", "fail", 1.0))]
    slow = [_mock_scanner(_result("llm_judge", "pass", 0.9))]
    pipeline = TieredScanPipeline(fast, slow)

    result = await pipeline.run(_pkg(), [])
    assert len(result.fast_results) == 1
    assert result.fast_results[0].verdict == "fail"
    assert len(result.slow_results) == 0
    assert result.llm_deferred is False
    slow[0].scan.assert_not_called()


async def test_case2_warning_runs_slow_sync():
    """Case 2: Static warns — run LLM synchronously."""
    fast = [
        _mock_scanner(_result("ioc_check", "pass", 1.0)),
        _mock_scanner(_result("static_analysis", "warn", 0.7)),
    ]
    slow = [_mock_scanner(_result("llm_judge", "warn", 0.6))]
    pipeline = TieredScanPipeline(fast, slow)

    result = await pipeline.run(_pkg(), [])
    assert len(result.fast_results) == 2
    assert len(result.slow_results) == 1
    assert result.slow_results[0].verdict == "warn"
    assert result.llm_deferred is False
    slow[0].scan.assert_called_once()


async def test_case3_hooks_present_runs_slow_sync():
    """Case 3: All pass but install hooks → run LLM synchronously."""
    fast = [
        _mock_scanner(_result("ioc_check", "pass", 1.0)),
        _mock_scanner(_result("static_analysis", "pass", 0.9)),
    ]
    slow = [_mock_scanner(_result("llm_judge", "pass", 0.95))]
    pipeline = TieredScanPipeline(fast, slow)

    result = await pipeline.run(_pkg(), [], has_install_hooks=True)
    assert len(result.slow_results) == 1
    assert result.llm_deferred is False
    assert result.has_install_hooks is True
    slow[0].scan.assert_called_once()


async def test_case4_clean_no_hooks_defers_llm():
    """Case 4: All pass, no hooks → defer LLM to background."""
    fast = [
        _mock_scanner(_result("ioc_check", "pass", 1.0)),
        _mock_scanner(_result("static_analysis", "pass", 0.9)),
    ]
    slow = [_mock_scanner(_result("llm_judge", "pass", 0.9))]
    pipeline = TieredScanPipeline(fast, slow)

    result = await pipeline.run(_pkg(), [], has_install_hooks=False)
    assert len(result.fast_results) == 2
    assert len(result.slow_results) == 0
    assert result.llm_deferred is True
    slow[0].scan.assert_not_called()


async def test_no_slow_scanners():
    """No slow scanners configured → fast results only, never deferred."""
    fast = [_mock_scanner(_result("static_analysis", "pass", 0.9))]
    pipeline = TieredScanPipeline(fast, [])

    result = await pipeline.run(_pkg(), [])
    assert len(result.fast_results) == 1
    assert result.llm_deferred is False


async def test_case2_fail_also_triggers_slow():
    """Case 2: Static fail (non-critical) → run LLM synchronously."""
    fast = [
        _mock_scanner(_result("ioc_check", "pass", 1.0)),
        _mock_scanner(_result("static_analysis", "fail", 0.7)),
    ]
    slow = [_mock_scanner(_result("llm_judge", "fail", 0.9))]
    pipeline = TieredScanPipeline(fast, slow)

    result = await pipeline.run(_pkg(), [])
    assert len(result.slow_results) == 1
    assert result.llm_deferred is False
