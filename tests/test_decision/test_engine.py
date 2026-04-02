"""Tests for decision engine."""

import pytest

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.schemas.scan import ScanResult


@pytest.fixture
def engine(settings: Settings) -> DecisionEngine:
    return DecisionEngine(settings)


@pytest.fixture
def enforce_engine(enforce_settings: Settings) -> DecisionEngine:
    return DecisionEngine(enforce_settings)


def _result(scanner: str, verdict: str, confidence: float) -> ScanResult:
    return ScanResult(
        scanner_name=scanner,
        verdict=verdict,
        confidence=confidence,
        details=f"{scanner}: {verdict}",
    )


async def test_all_pass_allows(engine: DecisionEngine) -> None:
    results = [
        _result("cooldown", "pass", 1.0),
        _result("static_analysis", "pass", 0.9),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "allow"
    assert decision.final_score < 0.3


async def test_cooldown_fail_only_quarantine(engine: DecisionEngine) -> None:
    """Cooldown fail alone: 0.3 * 1.0 * 1.0 = 0.3 -> quarantine boundary."""
    results = [
        _result("cooldown", "fail", 1.0),
        _result("static_analysis", "pass", 0.9),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "quarantine"


async def test_static_fail_only_quarantine(engine: DecisionEngine) -> None:
    """Static fail alone: 0.4 * 1.0 * 0.9 = 0.36 -> quarantine."""
    results = [
        _result("cooldown", "pass", 1.0),
        _result("static_analysis", "fail", 0.9),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "quarantine"


async def test_both_fail_deny(engine: DecisionEngine) -> None:
    """Both fail: 0.3 * 1.0 * 1.0 + 0.4 * 1.0 * 0.95 = 0.68 -> just under deny.
    With confidence=1.0: 0.3 + 0.4 = 0.7 -> deny."""
    results = [
        _result("cooldown", "fail", 1.0),
        _result("static_analysis", "fail", 1.0),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "deny"


async def test_warn_mode_deny_still_logged(engine: DecisionEngine) -> None:
    """In warn mode, deny verdict is computed but mode=warn."""
    results = [
        _result("cooldown", "fail", 1.0),
        _result("static_analysis", "fail", 1.0),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "deny"
    assert decision.mode == "warn"


async def test_enforce_mode(enforce_engine: DecisionEngine) -> None:
    results = [
        _result("cooldown", "fail", 1.0),
        _result("static_analysis", "fail", 1.0),
    ]
    decision = enforce_engine.decide(results)
    assert decision.verdict == "deny"
    assert decision.mode == "enforce"


async def test_empty_results_allow(engine: DecisionEngine) -> None:
    decision = engine.decide([])
    assert decision.verdict == "allow"
    assert decision.final_score == 0.0


async def test_warn_verdict_with_medium_confidence(engine: DecisionEngine) -> None:
    """cooldown warn: 0.3 * 0.5 * 0.7 = 0.105, static pass: 0 -> allow."""
    results = [
        _result("cooldown", "warn", 0.7),
        _result("static_analysis", "pass", 0.9),
    ]
    decision = engine.decide(results)
    assert decision.verdict == "allow"


async def test_score_calculation_precision(engine: DecisionEngine) -> None:
    """Verify exact score: cooldown fail(0.8) + static warn(0.6).
    = 0.3 * 1.0 * 0.8 + 0.4 * 0.5 * 0.6 = 0.24 + 0.12 = 0.36 -> quarantine."""
    results = [
        _result("cooldown", "fail", 0.8),
        _result("static_analysis", "warn", 0.6),
    ]
    decision = engine.decide(results)
    assert abs(decision.final_score - 0.36) < 0.001
    assert decision.verdict == "quarantine"
