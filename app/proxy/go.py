"""Go module proxy with security scanning."""

import shutil

from fastapi import APIRouter, Request, Response
from loguru import logger

from app.api.routers.metrics import increment
from app.core.config import Settings
from app.core.exceptions import PackageBlockedError
from app.db.audit_service import AuditService
from app.db.cache_service import CacheService
from app.decision.engine import DecisionEngine
from app.notifications import NotificationService
from app.registry.go_client import GoRegistryClient
from app.scanners.background import BackgroundScanManager
from app.scanners.base import ScanPipeline, TieredScanPipeline
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.utils.hash import compute_sha256
from app.utils.install_hooks import detect_install_hooks
from app.utils.tarball import extract_go_module_zip


class GoProxy:
    """Go module transparent proxy with zip interception and scanning."""

    def __init__(
        self,
        settings: Settings,
        registry_client: GoRegistryClient,
        scan_pipeline: ScanPipeline | TieredScanPipeline,
        decision_engine: DecisionEngine,
        cache_service: CacheService | None = None,
        audit_service: AuditService | None = None,
        bg_manager: BackgroundScanManager | None = None,
        notification_service: NotificationService | None = None,
    ) -> None:
        self._settings = settings
        self._registry = registry_client
        self._pipeline = scan_pipeline
        self._engine = decision_engine
        self._cache = cache_service
        self._audit = audit_service
        self._bg_manager = bg_manager
        self._notifications = notification_service

    def get_router(self) -> APIRouter:
        router = APIRouter()

        # Zip download (must be before generic pass-through)
        router.add_api_route(
            "/{module:path}/@v/{version}.zip",
            self.handle_zip_download,
            methods=["GET"],
        )
        # Version list
        router.add_api_route(
            "/{module:path}/@v/list",
            self.handle_passthrough,
            methods=["GET"],
        )
        # Version info
        router.add_api_route(
            "/{module:path}/@v/{version}.info",
            self.handle_passthrough,
            methods=["GET"],
        )
        # go.mod file
        router.add_api_route(
            "/{module:path}/@v/{version}.mod",
            self.handle_passthrough,
            methods=["GET"],
        )
        # Latest version
        router.add_api_route(
            "/{module:path}/@latest",
            self.handle_passthrough,
            methods=["GET"],
        )

        return router

    async def handle_passthrough(self, request: Request, module: str, **kwargs: str) -> Response:
        """Forward metadata requests to upstream."""
        path = request.url.path
        logger.debug("Go passthrough: {path}", path=path)

        encoded = GoRegistryClient.encode_module_path(module)
        # Reconstruct the path after the module with the encoded version
        suffix = path[path.index("/@") :]  # e.g. /@v/list, /@v/v1.0.0.info, /@latest
        upstream_path = f"/{encoded}{suffix}"

        try:
            response = await self._registry._client.get(upstream_path)
        except Exception as e:
            logger.error("Go upstream error: {err}", err=str(e))
            return Response(content="Upstream error", status_code=502)

        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "text/plain"),
        )

    async def handle_zip_download(self, request: Request, module: str, version: str) -> Response:
        """Intercept .zip download, scan, then allow or block."""
        logger.info("Go zip download: {mod}@{ver}", mod=module, ver=version)

        # Download zip from upstream
        content = await self._registry.download_zip(module, version)

        # Check cache
        content_hash = compute_sha256(content)
        if self._cache:
            cached = await self._cache.get("go", module, version, content_hash)
            if cached is not None:
                logger.info("Cache hit for {mod}@{ver}", mod=module, ver=version)
                decision = cached.model_copy(update={"mode": self._settings.decision_mode})
                return await self._apply_decision(
                    module, version, decision, content, f"{version}.zip", str(request.url.path)
                )

        # Extract and scan
        tmp_dir = None
        try:
            artifacts, tmp_dir = extract_go_module_zip(content)

            package_info = PackageInfo(
                name=module,
                version=version,
                registry="go",
            )

            if isinstance(self._pipeline, TieredScanPipeline):
                has_hooks = detect_install_hooks("go", "", artifacts, {})
                tiered = await self._pipeline.run(package_info, artifacts, has_install_hooks=has_hooks)
                all_results = tiered.fast_results + tiered.slow_results
                decision = self._engine.decide(all_results)
                decision = decision.model_copy(update={"llm_deferred": tiered.llm_deferred})

                if tiered.llm_deferred and self._bg_manager:
                    self._bg_manager.schedule("go", package_info, artifacts, tmp_dir, content_hash, tiered.fast_results)
                    tmp_dir = None
                elif self._cache:
                    await self._cache.put("go", module, version, content_hash, decision)
            else:
                scan_results = await self._pipeline.run(package_info, artifacts)
                decision = self._engine.decide(scan_results)
                if self._cache:
                    await self._cache.put("go", module, version, content_hash, decision)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return await self._apply_decision(module, version, decision, content, f"{version}.zip", str(request.url.path))

    async def _apply_decision(
        self,
        module: str,
        version: str,
        decision: DecisionResult,
        content: bytes,
        filename: str,
        request_path: str,
    ) -> Response:
        deferred_tag = " [LLM deferred]" if decision.llm_deferred else ""
        logger.info(
            "Decision for {mod}@{ver}: {verdict} (score={score:.4f}, mode={mode}){tag}",
            mod=module,
            ver=version,
            verdict=decision.verdict,
            score=decision.final_score,
            mode=decision.mode,
            tag=deferred_tag,
        )

        # Metrics
        increment("scans_total")
        increment(f"scan_{decision.verdict}")

        if self._audit:
            await self._audit.log_decision("go", module, version, decision, request_path)

        # Notifications
        if self._notifications:
            await self._notifications.notify_decision("go", module, version, decision)

        if decision.verdict == "deny" and decision.mode == "enforce":
            raise PackageBlockedError(package_name=module, version=version, reason=decision.reason)

        if decision.verdict in ("deny", "quarantine"):
            logger.warning(
                "Go {verdict} for {mod}@{ver}",
                verdict=decision.verdict.upper(),
                mod=module,
                ver=version,
            )

        return Response(
            content=content,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
