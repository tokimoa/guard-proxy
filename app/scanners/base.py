"""Scanner protocol and pipeline."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from loguru import logger
from pydantic import BaseModel

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


@runtime_checkable
class ScannerProtocol(Protocol):
    """Interface that all scanners must implement."""

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult: ...


class ScanPipeline:
    """Execute a sequence of scanners and collect results.

    All scanners run regardless of individual results — the decision engine
    (not the pipeline) determines the final verdict from combined results.
    """

    def __init__(self, scanners: list[ScannerProtocol]) -> None:
        self._scanners = scanners

    async def run(self, package: PackageInfo, artifacts: list[Path]) -> list[ScanResult]:
        results: list[ScanResult] = []
        for scanner in self._scanners:
            try:
                result = await scanner.scan(package, artifacts)
                results.append(result)
                logger.info(
                    "Scanner {scanner} verdict={verdict} confidence={confidence:.2f}",
                    scanner=result.scanner_name,
                    verdict=result.verdict,
                    confidence=result.confidence,
                )
            except Exception:
                logger.exception("Scanner failed: {scanner}", scanner=type(scanner).__name__)
                results.append(
                    ScanResult(
                        scanner_name=type(scanner).__name__,
                        verdict="warn",
                        confidence=0.5,
                        details=f"Scanner {type(scanner).__name__} encountered an error",
                        metadata={"error": True},
                    )
                )
        return results


class TieredScanResult(BaseModel):
    """Result from two-tier scanning."""

    fast_results: list[ScanResult]
    slow_results: list[ScanResult] = []
    llm_deferred: bool = False
    has_install_hooks: bool = False


class TieredScanPipeline:
    """Two-tier pipeline: fast scanners always run, slow scanners run conditionally.

    Decision logic:
      Case 1: Fast tier finds critical/IOC hit → skip slow tier (block immediately)
      Case 2: Fast tier finds warn/fail → run slow tier synchronously
      Case 3: All pass + install hooks present → run slow tier synchronously
      Case 4: All pass + no hooks → skip slow tier (defer to background)
    """

    def __init__(
        self,
        fast_scanners: list[ScannerProtocol],
        slow_scanners: list[ScannerProtocol],
    ) -> None:
        self._fast = fast_scanners
        self._slow = slow_scanners

    async def run(
        self,
        package: PackageInfo,
        artifacts: list[Path],
        has_install_hooks: bool = False,
    ) -> TieredScanResult:
        # Always run fast tier
        fast_results = await self._run_scanners(self._fast, package, artifacts)

        # No slow scanners configured → return fast results only
        if not self._slow:
            return TieredScanResult(fast_results=fast_results, has_install_hooks=has_install_hooks)

        # Case 1: Critical/IOC hit — block immediately, no LLM needed
        has_critical = any(r.verdict == "fail" and r.confidence >= 0.9 for r in fast_results)
        if has_critical:
            logger.info("Critical threat detected — skipping LLM, blocking immediately")
            return TieredScanResult(fast_results=fast_results, has_install_hooks=has_install_hooks)

        # Case 2: Code-analysis warnings/failures — run LLM synchronously
        # Only static analysis, heuristics, and IOC warnings trigger LLM (not advisory/metadata/cooldown)
        _CODE_SCANNERS = {"static_analysis", "heuristics_check", "ioc_check", "ast_analysis", "yara_scan"}
        has_code_warnings = any(
            r.verdict in ("warn", "fail") and r.scanner_name in _CODE_SCANNERS for r in fast_results
        )
        if has_code_warnings:
            logger.info("Suspicious code patterns found — running LLM synchronously")
            slow_results = await self._run_scanners(self._slow, package, artifacts)
            return TieredScanResult(
                fast_results=fast_results, slow_results=slow_results, has_install_hooks=has_install_hooks
            )

        # Case 3: All pass + install hooks — run LLM synchronously (security-critical)
        if has_install_hooks:
            logger.info("Install hooks detected — running LLM synchronously")
            slow_results = await self._run_scanners(self._slow, package, artifacts)
            return TieredScanResult(
                fast_results=fast_results, slow_results=slow_results, has_install_hooks=has_install_hooks
            )

        # Case 4: All pass + no hooks — defer LLM to background
        logger.info("No threats or hooks — deferring LLM to background")
        return TieredScanResult(fast_results=fast_results, llm_deferred=True, has_install_hooks=has_install_hooks)

    @staticmethod
    async def _run_scanners(
        scanners: list[ScannerProtocol], package: PackageInfo, artifacts: list[Path]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        for scanner in scanners:
            try:
                result = await scanner.scan(package, artifacts)
                results.append(result)
                logger.info(
                    "Scanner {scanner} verdict={verdict} confidence={confidence:.2f}",
                    scanner=result.scanner_name,
                    verdict=result.verdict,
                    confidence=result.confidence,
                )
            except Exception:
                logger.exception("Scanner failed: {scanner}", scanner=type(scanner).__name__)
                results.append(
                    ScanResult(
                        scanner_name=type(scanner).__name__,
                        verdict="warn",
                        confidence=0.5,
                        details=f"Scanner {type(scanner).__name__} encountered an error",
                        metadata={"error": True},
                    )
                )
        return results
