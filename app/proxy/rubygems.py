"""RubyGems registry proxy with security scanning."""

import re
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
from app.registry.rubygems_client import RubyGemsRegistryClient
from app.scanners.background import BackgroundScanManager
from app.scanners.base import ScanPipeline, TieredScanPipeline
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.utils.hash import compute_sha256
from app.utils.install_hooks import detect_install_hooks
from app.utils.tarball import extract_gem_files

_VERSION_PATTERN = re.compile(r"^(.+?)-(\d+\..+?)\.gem$")


class RubyGemsProxy:
    """RubyGems transparent proxy with gem interception and scanning."""

    def __init__(
        self,
        settings: Settings,
        registry_client: RubyGemsRegistryClient,
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

        # Scan route (must be before catch-all)
        router.add_api_route("/gems/{gem_filename}", self.handle_gem_download, methods=["GET"])

        # Compact Index pass-through
        router.add_api_route("/info/{gem_name}", self.handle_passthrough_with_gem_name, methods=["GET"])
        router.add_api_route("/versions", self.handle_passthrough, methods=["GET"])
        router.add_api_route("/names", self.handle_passthrough, methods=["GET"])

        # Legacy index pass-through
        router.add_api_route("/specs.4.8.gz", self.handle_passthrough, methods=["GET"])
        router.add_api_route("/latest_specs.4.8.gz", self.handle_passthrough, methods=["GET"])
        router.add_api_route("/prerelease_specs.4.8.gz", self.handle_passthrough, methods=["GET"])

        # Quick spec pass-through
        router.add_api_route("/quick/Marshal.4.8/{path:path}", self.handle_passthrough_with_path, methods=["GET"])

        # API pass-through
        router.add_api_route("/api/{path:path}", self.handle_passthrough_with_path, methods=["GET"])

        return router

    async def handle_passthrough(self, request: Request) -> Response:
        """Forward request to upstream, preserving caching headers.

        Modern gem/bundler uses ETag, Range, and Repr-Digest for efficient
        Compact Index caching. We must forward these transparently.
        """
        path = request.url.path
        headers = dict(request.headers)
        response = await self._registry.forward_request(path, headers)

        # Preserve headers critical for Compact Index caching
        resp_headers: dict[str, str] = {}
        for header in ("etag", "repr-digest", "cache-control", "last-modified", "accept-ranges"):
            val = response.headers.get(header)
            if val:
                resp_headers[header] = val

        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type"),
            headers=resp_headers,
        )

    async def handle_passthrough_with_path(self, request: Request, path: str) -> Response:  # noqa: ARG002
        """Forward request with path parameter to upstream."""
        return await self.handle_passthrough(request)

    async def handle_passthrough_with_gem_name(self, request: Request, gem_name: str) -> Response:  # noqa: ARG002
        """Forward Compact Index info request to upstream."""
        return await self.handle_passthrough(request)

    async def handle_gem_download(self, request: Request, gem_filename: str) -> Response:
        """Intercept .gem download, scan, then allow or block."""
        gem_name, version = self._extract_name_version(gem_filename)
        logger.info("Gem download: {gem}@{ver}", gem=gem_name, ver=version)

        # Download from upstream
        content = await self._registry.download_gem(gem_filename)

        # Check cache
        content_hash = compute_sha256(content)
        if self._cache:
            cached = await self._cache.get("rubygems", gem_name, version, content_hash)
            if cached is not None:
                logger.info("Cache hit for {gem}@{ver}", gem=gem_name, ver=version)
                decision = cached.model_copy(update={"mode": self._settings.decision_mode})
                return await self._apply_decision(
                    gem_name, version, decision, content, gem_filename, str(request.url.path)
                )

        # Extract and scan
        tmp_dir = None
        try:
            artifacts, tmp_dir = extract_gem_files(content, gem_filename)

            # Fetch publish date and metadata for scanners
            publish_date = None
            scan_metadata: dict = {}
            try:
                versions = await self._registry.get_gem_versions(gem_name)
                publish_date = RubyGemsRegistryClient.extract_publish_date(versions, version)
                gem_info = await self._registry.get_gem_metadata(gem_name)
                scan_metadata = {"authors": gem_info.get("authors", "")}
            except Exception:
                logger.warning(
                    "Could not fetch metadata for {gem}@{ver}, proceeding with scan",
                    gem=gem_name,
                    ver=version,
                )

            package_info = PackageInfo(
                name=gem_name,
                version=version,
                registry="rubygems",
                publish_date=publish_date,
                metadata=scan_metadata,
            )

            # Tiered or classic pipeline
            if isinstance(self._pipeline, TieredScanPipeline):
                has_hooks = detect_install_hooks("rubygems", gem_filename, artifacts, {})
                tiered = await self._pipeline.run(package_info, artifacts, has_install_hooks=has_hooks)
                all_results = tiered.fast_results + tiered.slow_results
                decision = self._engine.decide(all_results)
                decision = decision.model_copy(update={"llm_deferred": tiered.llm_deferred})

                if tiered.llm_deferred and self._bg_manager:
                    self._bg_manager.schedule(
                        "rubygems", package_info, artifacts, tmp_dir, content_hash, tiered.fast_results
                    )
                    tmp_dir = None
                elif self._cache:
                    await self._cache.put("rubygems", gem_name, version, content_hash, decision)
            else:
                scan_results = await self._pipeline.run(package_info, artifacts)
                decision = self._engine.decide(scan_results)
                if self._cache:
                    await self._cache.put("rubygems", gem_name, version, content_hash, decision)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return await self._apply_decision(gem_name, version, decision, content, gem_filename, str(request.url.path))

    async def _apply_decision(
        self,
        gem_name: str,
        version: str,
        decision: DecisionResult,
        content: bytes,
        filename: str,
        request_path: str,
    ) -> Response:
        deferred_tag = " [LLM deferred]" if decision.llm_deferred else ""
        logger.info(
            "Decision for {gem}@{ver}: {verdict} (score={score:.4f}, mode={mode}){tag}",
            gem=gem_name,
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
            await self._audit.log_decision("rubygems", gem_name, version, decision, request_path)

        # Notifications
        if self._notifications:
            await self._notifications.notify_decision("rubygems", gem_name, version, decision)

        if decision.verdict == "deny" and decision.mode == "enforce":
            raise PackageBlockedError(package_name=gem_name, version=version, reason=decision.reason)

        if decision.verdict in ("deny", "quarantine"):
            logger.warning(
                "RubyGems {verdict} for {gem}@{ver}",
                verdict=decision.verdict.upper(),
                gem=gem_name,
                ver=version,
            )

        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @staticmethod
    def _extract_name_version(filename: str) -> tuple[str, str]:
        """Extract gem name and version from filename like 'nokogiri-1.16.0.gem'."""
        m = _VERSION_PATTERN.match(filename)
        if m:
            return m.group(1), m.group(2)
        base = filename.removesuffix(".gem")
        parts = base.rsplit("-", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return base, "unknown"
