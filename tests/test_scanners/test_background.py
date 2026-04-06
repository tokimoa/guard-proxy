"""Tests for BackgroundScanManager."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.decision.engine import DecisionEngine
from app.scanners.background import BackgroundScanManager
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


def _make_package() -> PackageInfo:
    return PackageInfo(name="test-pkg", version="1.0.0", registry="npm")


def _make_scan_result(verdict: str = "pass", confidence: float = 0.9) -> ScanResult:
    return ScanResult(scanner_name="test", verdict=verdict, confidence=confidence, details="test")


def _make_decision(verdict: str = "allow", score: float = 0.1) -> DecisionResult:
    return DecisionResult(
        verdict=verdict,
        final_score=score,
        scan_results=[_make_scan_result()],
        reason="test",
        mode="warn",
    )


@pytest.fixture()
def mock_engine():
    engine = MagicMock(spec=DecisionEngine)
    engine.decide.return_value = _make_decision("allow", 0.1)
    return engine


@pytest.fixture()
def mock_cache():
    cache = AsyncMock()
    cache.put = AsyncMock()
    return cache


@pytest.fixture()
def mock_audit():
    audit = AsyncMock()
    audit.log_decision = AsyncMock()
    return audit


@pytest.fixture()
def mock_scanner():
    scanner = AsyncMock()
    scanner.scan = AsyncMock(return_value=_make_scan_result("pass", 0.9))
    return scanner


class TestSchedule:
    async def test_creates_task(self, mock_engine, mock_scanner, tmp_path):
        mgr = BackgroundScanManager([mock_scanner], mock_engine)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        assert len(mgr._tasks) == 1
        # Wait for task to complete
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

    async def test_task_removed_on_completion(self, mock_engine, mock_scanner, tmp_path):
        mgr = BackgroundScanManager([mock_scanner], mock_engine)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)
        # done_callback should have removed the task
        assert len(mgr._tasks) == 0


class TestRun:
    async def test_runs_slow_scanners(self, mock_engine, mock_scanner, mock_cache, tmp_path):
        mgr = BackgroundScanManager([mock_scanner], mock_engine, mock_cache)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [_make_scan_result()])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        mock_scanner.scan.assert_called_once()
        mock_engine.decide.assert_called_once()
        mock_cache.put.assert_called_once()

    async def test_updates_audit(self, mock_engine, mock_scanner, mock_cache, mock_audit, tmp_path):
        mgr = BackgroundScanManager([mock_scanner], mock_engine, mock_cache, mock_audit)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        mock_audit.log_decision.assert_called_once()
        args = mock_audit.log_decision.call_args
        assert args[0][0] == "npm"
        assert args[0][4] == "background-scan"

    async def test_caps_deny_to_quarantine_when_fast_all_pass(self, mock_scanner, mock_cache, tmp_path):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.return_value = _make_decision("deny", 0.9)

        mgr = BackgroundScanManager([mock_scanner], engine, mock_cache)
        fast_results = [_make_scan_result("pass", 0.9)]
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", fast_results)
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        # Should cap deny to quarantine
        cached_decision = mock_cache.put.call_args[0][4]
        assert cached_decision.verdict == "quarantine"

    async def test_does_not_cap_when_fast_has_failures(self, mock_scanner, mock_cache, tmp_path):
        engine = MagicMock(spec=DecisionEngine)
        engine.decide.return_value = _make_decision("deny", 0.9)

        mgr = BackgroundScanManager([mock_scanner], engine, mock_cache)
        fast_results = [_make_scan_result("fail", 0.9)]
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", fast_results)
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        cached_decision = mock_cache.put.call_args[0][4]
        assert cached_decision.verdict == "deny"

    async def test_scanner_exception_does_not_crash(self, mock_engine, mock_cache, tmp_path):
        failing_scanner = AsyncMock()
        failing_scanner.scan = AsyncMock(side_effect=RuntimeError("scanner exploded"))

        mgr = BackgroundScanManager([failing_scanner], mock_engine, mock_cache)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        # Should still call decide with fast_results only
        mock_engine.decide.assert_called_once()

    async def test_cleans_up_tmp_dir(self, mock_engine, mock_scanner, tmp_path):
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        (work_dir / "file.txt").write_text("test")

        mgr = BackgroundScanManager([mock_scanner], mock_engine)
        mgr.schedule("npm", _make_package(), [], work_dir, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        assert not work_dir.exists()

    async def test_cleans_up_tmp_dir_on_exception(self, mock_engine, tmp_path):
        work_dir = tmp_path / "work"
        work_dir.mkdir()

        engine = MagicMock(spec=DecisionEngine)
        engine.decide.side_effect = RuntimeError("decide failed")

        failing_scanner = AsyncMock()
        failing_scanner.scan = AsyncMock(return_value=_make_scan_result())

        mgr = BackgroundScanManager([failing_scanner], engine)
        mgr.schedule("npm", _make_package(), [], work_dir, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)

        assert not work_dir.exists()

    async def test_works_without_cache(self, mock_engine, mock_scanner, tmp_path):
        mgr = BackgroundScanManager([mock_scanner], mock_engine, cache_service=None)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        await asyncio.gather(*mgr._tasks, return_exceptions=True)
        # No exception means it handled None cache gracefully


class TestShutdown:
    async def test_cancels_pending_tasks(self, mock_engine, tmp_path):
        slow_scanner = AsyncMock()
        slow_scanner.scan = AsyncMock(side_effect=asyncio.CancelledError)

        mgr = BackgroundScanManager([slow_scanner], mock_engine)
        mgr.schedule("npm", _make_package(), [], tmp_path, "hash123", [])
        await mgr.shutdown()

    async def test_shutdown_with_no_tasks(self, mock_engine):
        mgr = BackgroundScanManager([], mock_engine)
        await mgr.shutdown()  # Should not raise
