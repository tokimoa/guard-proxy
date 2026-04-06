"""Tests for NotificationService."""

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.notifications import _RATE_LIMIT_MAX, NotificationService
from app.schemas.decision import DecisionResult
from app.schemas.scan import ScanResult


def _make_decision(verdict: str = "deny", score: float = 0.9) -> DecisionResult:
    return DecisionResult(
        verdict=verdict,
        final_score=score,
        scan_results=[ScanResult(scanner_name="test", verdict="fail", confidence=0.9, details="test")],
        reason="test reason",
        mode="enforce",
    )


class TestNotificationServiceInit:
    def test_enabled_with_url(self):
        svc = NotificationService("https://hooks.slack.com/test")
        assert svc._enabled is True

    def test_disabled_without_url(self):
        svc = NotificationService(None)
        assert svc._enabled is False

    def test_disabled_with_empty_string(self):
        svc = NotificationService("")
        assert svc._enabled is False


class TestNotifyDecision:
    @pytest.fixture()
    def svc(self):
        return NotificationService("https://hooks.slack.com/test")

    async def test_skips_allow_verdict(self, svc):
        decision = _make_decision("allow", 0.1)
        with patch("httpx.AsyncClient.post") as mock_post:
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
            mock_post.assert_not_called()

    async def test_skips_when_disabled(self):
        svc = NotificationService(None)
        decision = _make_decision("deny")
        with patch("httpx.AsyncClient.post") as mock_post:
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
            mock_post.assert_not_called()

    async def test_sends_deny_notification(self, svc):
        decision = _make_decision("deny")
        mock_response = AsyncMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
            await svc.notify_decision("npm", "evil-pkg", "1.0.0", decision)
            mock_post.assert_called_once()
            payload = mock_post.call_args[1]["json"]
            text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            assert "evil-pkg@1.0.0" in text
            assert "DENY" in text
            assert ":no_entry:" in text

    async def test_sends_quarantine_notification(self, svc):
        decision = _make_decision("quarantine", 0.5)
        mock_response = AsyncMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
            await svc.notify_decision("pypi", "sus-pkg", "2.0.0", decision)
            payload = mock_post.call_args[1]["json"]
            text = payload["attachments"][0]["blocks"][0]["text"]["text"]
            assert "QUARANTINE" in text
            assert ":warning:" in text
            assert payload["attachments"][0]["color"] == "#ff9900"

    async def test_logs_warning_on_non_200(self, svc):
        decision = _make_decision("deny")
        mock_response = AsyncMock()
        mock_response.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
            # Should not raise, just log warning

    async def test_handles_http_exception(self, svc):
        decision = _make_decision("deny")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.ConnectError("timeout")):
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
            # Should not raise

    async def test_records_send_time_on_success(self, svc):
        decision = _make_decision("deny")
        mock_response = AsyncMock()
        mock_response.status_code = 200

        assert len(svc._send_times) == 0
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
        assert len(svc._send_times) == 1

    async def test_does_not_record_send_time_on_exception(self, svc):
        decision = _make_decision("deny")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=Exception("fail")):
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
        assert len(svc._send_times) == 0


class TestRateLimiting:
    def test_not_limited_initially(self):
        svc = NotificationService("https://hooks.slack.com/test")
        assert svc._is_rate_limited() is False

    def test_limited_after_max_sends(self):
        svc = NotificationService("https://hooks.slack.com/test")
        now = time.monotonic()
        svc._send_times = [now] * _RATE_LIMIT_MAX
        assert svc._is_rate_limited() is True

    def test_evicts_old_entries(self):
        svc = NotificationService("https://hooks.slack.com/test")
        old = time.monotonic() - 120  # 2 minutes ago, outside 60s window
        svc._send_times = [old] * _RATE_LIMIT_MAX
        assert svc._is_rate_limited() is False
        assert len(svc._send_times) == 0

    async def test_rate_limited_skips_send(self):
        svc = NotificationService("https://hooks.slack.com/test")
        now = time.monotonic()
        svc._send_times = [now] * _RATE_LIMIT_MAX
        decision = _make_decision("deny")

        with patch("httpx.AsyncClient.post") as mock_post:
            await svc.notify_decision("npm", "pkg", "1.0.0", decision)
            mock_post.assert_not_called()
