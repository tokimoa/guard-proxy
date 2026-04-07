"""Cargo (crates.io) registry proxy with security scanning."""

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
from app.registry.cargo_client import CargoRegistryClient
from app.scanners.background import BackgroundScanManager
from app.scanners.base import ScanPipeline, TieredScanPipeline
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.utils.hash import compute_sha256
from app.utils.install_hooks import detect_install_hooks
from app.utils.tarball import extract_cargo_crate


class CargoProxy:
    """Cargo transparent proxy with .crate interception and scanning."""

    def __init__(
        self,
        settings: Settings,
        registry_client: CargoRegistryClient,
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

        # Crate download: GET /api/v1/crates/{name}/{version}/download
        router.add_api_route(
            "/api/v1/crates/{crate_name}/{version}/download",
            self.handle_crate_download,
            methods=["GET"],
        )
        # Crate metadata: GET /api/v1/crates/{name}
        router.add_api_route(
            "/api/v1/crates/{crate_name}",
            self.handle_passthrough,
            methods=["GET"],
        )
        # Version metadata: GET /api/v1/crates/{name}/{version}
        router.add_api_route(
            "/api/v1/crates/{crate_name}/{version}",
            self.handle_passthrough,
            methods=["GET"],
        )

        return router

    async def handle_passthrough(self, request: Request, **kwargs: str) -> Response:
        """Forward metadata requests to upstream."""
        path = request.url.path
        logger.debug("Cargo passthrough: {path}", path=path)

        try:
            response = await self._registry.forward_request(path)
        except Exception as e:
            logger.error("Cargo upstream error: {err}", err=str(e))
            return Response(content="Upstream error", status_code=502)

        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "application/json"),
        )

    async def handle_crate_download(self, request: Request, crate_name: str, version: str) -> Response:
        """Intercept .crate download, scan, then allow or block."""
        logger.info("Cargo download: {crate}@{ver}", crate=crate_name, ver=version)

        content = await self._registry.download_crate(crate_name, version)

        # Check cache
        content_hash = compute_sha256(content)
        if self._cache:
            cached = await self._cache.get("cargo", crate_name, version, content_hash)
            if cached is not None:
                logger.info("Cache hit for {crate}@{ver}", crate=crate_name, ver=version)
                decision = cached.model_copy(update={"mode": self._settings.decision_mode})
                return await self._apply_decision(
                    crate_name,
                    version,
                    decision,
                    content,
                    f"{crate_name}-{version}.crate",
                    str(request.url.path),
                )

        # Extract and scan
        tmp_dir = None
        try:
            artifacts, tmp_dir = extract_cargo_crate(content)

            # Fetch publish date and license
            publish_date = None
            scan_metadata: dict = {}
            try:
                meta = await self._registry.get_version_metadata(crate_name, version)
                publish_date = CargoRegistryClient.extract_publish_date(meta)
                version_info = meta.get("version", {})
                scan_metadata["license"] = version_info.get("license", "")
            except Exception:
                logger.warning(
                    "Could not fetch metadata for {crate}@{ver}, proceeding with scan",
                    crate=crate_name,
                    ver=version,
                )

            package_info = PackageInfo(
                name=crate_name,
                version=version,
                registry="cargo",
                publish_date=publish_date,
                metadata=scan_metadata,
            )

            if isinstance(self._pipeline, TieredScanPipeline):
                has_hooks = detect_install_hooks("cargo", "", artifacts, {})
                tiered = await self._pipeline.run(package_info, artifacts, has_install_hooks=has_hooks)
                all_results = tiered.fast_results + tiered.slow_results
                decision = self._engine.decide(all_results)
                decision = decision.model_copy(update={"llm_deferred": tiered.llm_deferred})

                if tiered.llm_deferred and self._bg_manager:
                    self._bg_manager.schedule(
                        "cargo", package_info, artifacts, tmp_dir, content_hash, tiered.fast_results
                    )
                    tmp_dir = None
                elif self._cache:
                    await self._cache.put("cargo", crate_name, version, content_hash, decision)
            else:
                scan_results = await self._pipeline.run(package_info, artifacts)
                decision = self._engine.decide(scan_results)
                if self._cache:
                    await self._cache.put("cargo", crate_name, version, content_hash, decision)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return await self._apply_decision(
            crate_name,
            version,
            decision,
            content,
            f"{crate_name}-{version}.crate",
            str(request.url.path),
        )

    async def _apply_decision(
        self,
        crate_name: str,
        version: str,
        decision: DecisionResult,
        content: bytes,
        filename: str,
        request_path: str,
    ) -> Response:
        deferred_tag = " [LLM deferred]" if decision.llm_deferred else ""
        logger.info(
            "Decision for {crate}@{ver}: {verdict} (score={score:.4f}, mode={mode}){tag}",
            crate=crate_name,
            ver=version,
            verdict=decision.verdict,
            score=decision.final_score,
            mode=decision.mode,
            tag=deferred_tag,
        )

        increment("scans_total")
        increment(f"scan_{decision.verdict}")

        if self._audit:
            await self._audit.log_decision("cargo", crate_name, version, decision, request_path)

        if self._notifications:
            await self._notifications.notify_decision("cargo", crate_name, version, decision)

        if decision.verdict == "deny" and decision.mode == "enforce":
            raise PackageBlockedError(package_name=crate_name, version=version, reason=decision.reason)

        if decision.verdict in ("deny", "quarantine"):
            logger.warning(
                "Cargo {verdict} for {crate}@{ver}",
                verdict=decision.verdict.upper(),
                crate=crate_name,
                ver=version,
            )

        safe_filename = filename.replace('"', "").replace("\\", "").replace("\n", "").replace("\r", "")
        return Response(
            content=content,
            media_type="application/x-tar",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
        )
