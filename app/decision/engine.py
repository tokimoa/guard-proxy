"""Decision engine: weighted scoring from scanner results."""

from app.core.config import Settings
from app.schemas.decision import DecisionResult
from app.schemas.scan import ScanResult

_VERDICT_SCORES: dict[str, float] = {
    "pass": 0.0,
    "warn": 0.5,
    "fail": 1.0,
}


class DecisionEngine:
    """Combine scanner results via weighted scoring to produce a final verdict."""

    def __init__(self, settings: Settings) -> None:
        self._mode = settings.decision_mode
        self._warn_threshold = settings.warn_threshold
        self._deny_threshold = settings.deny_threshold
        self._weights: dict[str, float] = {
            "ioc_check": 1.0,
            "advisory_check": 0.9,
            "cooldown": settings.cooldown_weight,
            "metadata_check": 0.5,
            "static_analysis": settings.static_analysis_weight,
            "heuristics_check": 0.35,
            "ast_analysis": 0.65,
            "yara_scan": 0.55,
            "maintainer_check": 0.6,
            "dependency_check": 0.45,
            "llm_judge": settings.llm_weight,
        }

    def decide(self, scan_results: list[ScanResult]) -> DecisionResult:
        if not scan_results:
            return DecisionResult(
                verdict="allow",
                final_score=0.0,
                scan_results=[],
                reason="No scanners ran",
                mode=self._mode,
            )

        final_score = 0.0
        for result in scan_results:
            weight = self._weights.get(result.scanner_name, 0.3)
            verdict_score = _VERDICT_SCORES.get(result.verdict, 0.0)
            final_score += weight * verdict_score * result.confidence

        # Cap at 1.0 to prevent unbounded scores when many scanners fire
        final_score = round(min(final_score, 1.0), 4)

        if final_score >= self._deny_threshold:
            raw_verdict = "deny"
        elif final_score >= self._warn_threshold:
            raw_verdict = "quarantine"
        else:
            raw_verdict = "allow"

        reason = self._build_reason(scan_results, raw_verdict, final_score)

        return DecisionResult(
            verdict=raw_verdict,
            final_score=final_score,
            scan_results=scan_results,
            reason=reason,
            mode=self._mode,
        )

    @staticmethod
    def _build_reason(results: list[ScanResult], verdict: str, score: float) -> str:
        parts = [f"Score: {score:.4f} → {verdict}"]
        for r in results:
            parts.append(f"  [{r.scanner_name}] {r.verdict} (confidence={r.confidence:.2f}): {r.details[:120]}")
        return "\n".join(parts)
