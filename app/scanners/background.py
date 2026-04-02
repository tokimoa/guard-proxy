"""Background scan manager for deferred LLM scanning."""

import asyncio
import shutil
from pathlib import Path

from loguru import logger

from app.db.audit_service import AuditService
from app.db.cache_service import CacheService
from app.decision.engine import DecisionEngine
from app.scanners.base import ScannerProtocol
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


class BackgroundScanManager:
    """Run LLM scans in the background and update cache on completion."""

    def __init__(
        self,
        slow_scanners: list[ScannerProtocol],
        decision_engine: DecisionEngine,
        cache_service: CacheService | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self._slow = slow_scanners
        self._engine = decision_engine
        self._cache = cache_service
        self._audit = audit_service
        self._tasks: set[asyncio.Task] = set()  # type: ignore[type-arg]

    def schedule(
        self,
        registry: str,
        package: PackageInfo,
        artifacts: list[Path],
        tmp_dir: Path,
        content_hash: str,
        fast_results: list[ScanResult],
    ) -> None:
        """Schedule a background LLM scan. Takes ownership of tmp_dir."""
        task = asyncio.create_task(self._run(registry, package, artifacts, tmp_dir, content_hash, fast_results))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        logger.info(
            "Background LLM scan scheduled: {pkg}@{ver}",
            pkg=package.name,
            ver=package.version,
        )

    async def _run(
        self,
        registry: str,
        package: PackageInfo,
        artifacts: list[Path],
        tmp_dir: Path,
        content_hash: str,
        fast_results: list[ScanResult],
    ) -> None:
        try:
            slow_results: list[ScanResult] = []
            for scanner in self._slow:
                try:
                    result = await scanner.scan(package, artifacts)
                    slow_results.append(result)
                except Exception:
                    logger.exception("Background scanner failed: {s}", s=type(scanner).__name__)

            all_results = fast_results + slow_results
            decision = self._engine.decide(all_results)

            # Safety guard: if fast tier was all-pass, cap background verdict at quarantine
            # This prevents a single LLM misclassification from blocking legitimate packages
            fast_all_pass = all(r.verdict == "pass" for r in fast_results)
            if fast_all_pass and decision.verdict == "deny":
                logger.warning(
                    "Background scan would deny {pkg}@{ver} but fast tier was all-pass — capping at quarantine",
                    pkg=package.name,
                    ver=package.version,
                )
                decision = decision.model_copy(update={"verdict": "quarantine"})

            if self._cache:
                await self._cache.put(registry, package.name, package.version, content_hash, decision)

            if self._audit:
                await self._audit.log_decision(registry, package.name, package.version, decision, "background-scan")

            logger.info(
                "Background scan complete: {pkg}@{ver} → {verdict} (score={score:.4f})",
                pkg=package.name,
                ver=package.version,
                verdict=decision.verdict,
                score=decision.final_score,
            )
        except Exception:
            logger.exception("Background scan failed: {pkg}@{ver}", pkg=package.name, ver=package.version)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def shutdown(self) -> None:
        """Cancel all pending background tasks."""
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Background scan manager shut down ({n} tasks)", n=len(self._tasks))
