"""npm registry proxy with security scanning."""

import shutil
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response
from loguru import logger

from app.api.routers.metrics import increment
from app.core.config import Settings
from app.core.exceptions import PackageBlockedError
from app.db.audit_service import AuditService
from app.db.cache_service import CacheService
from app.decision.engine import DecisionEngine
from app.notifications import NotificationService
from app.registry.npm_client import NpmRegistryClient
from app.scanners.background import BackgroundScanManager
from app.scanners.base import ScanPipeline, TieredScanPipeline
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.utils.hash import compute_sha256
from app.utils.install_hooks import detect_install_hooks
from app.utils.tarball import extract_npm_install_scripts, parse_install_scripts


class NpmProxy:
    """npm transparent proxy with tarball interception and scanning."""

    def __init__(
        self,
        settings: Settings,
        registry_client: NpmRegistryClient,
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

        # Scoped package tarball: GET /@scope/pkg/-/tarball.tgz
        router.add_api_route(
            "/@{scope}/{package_name}/-/{tarball_filename}",
            self.handle_tarball_request,
            methods=["GET"],
        )
        # Unscoped package tarball: GET /pkg/-/tarball.tgz
        router.add_api_route(
            "/{package_name}/-/{tarball_filename}",
            self.handle_tarball_request,
            methods=["GET"],
        )
        # Scoped package metadata: GET /@scope/pkg
        router.add_api_route(
            "/@{scope}/{package_name}",
            self.handle_metadata_request,
            methods=["GET"],
        )
        # Unscoped package metadata: GET /pkg
        # Must be last to avoid catching other routes
        router.add_api_route(
            "/{package_name}",
            self.handle_metadata_request,
            methods=["GET"],
        )

        return router

    async def handle_metadata_request(
        self,
        request: Request,
        package_name: str,
        scope: str | None = None,
    ) -> Response:
        """Pass through metadata with tarball URL rewriting."""
        full_name = f"@{scope}/{package_name}" if scope else package_name
        logger.debug("Metadata request: {pkg}", pkg=full_name)

        metadata = await self._registry.get_package_metadata(full_name)

        # Rewrite tarball URLs to route through this proxy
        proxy_base = self._get_proxy_base_url(request)
        metadata = self._rewrite_tarball_urls(metadata, proxy_base)

        return Response(
            content=_json_bytes(metadata),
            media_type="application/json",
        )

    async def handle_tarball_request(
        self,
        request: Request,
        package_name: str,
        tarball_filename: str,
        scope: str | None = None,
    ) -> Response:
        """Intercept tarball download, scan, then allow or block."""
        full_name = f"@{scope}/{package_name}" if scope else package_name
        version = self._extract_version_from_tarball(package_name, tarball_filename)
        logger.info("Tarball request: {pkg}@{ver}", pkg=full_name, ver=version)

        # Fetch version metadata for publish date
        try:
            version_meta = await self._registry.get_version_metadata(full_name, version)
        except Exception:
            logger.warning("Could not fetch metadata for {pkg}@{ver}, proceeding with scan", pkg=full_name, ver=version)
            version_meta = None

        # Download tarball from upstream
        upstream_tarball_url = self._build_upstream_tarball_url(full_name, tarball_filename)
        tarball_content = await self._registry.download_tarball(upstream_tarball_url)

        # Check cache first
        content_hash = compute_sha256(tarball_content)
        if self._cache:
            cached = await self._cache.get("npm", full_name, version, content_hash)
            if cached is not None:
                logger.info("Cache hit for {pkg}@{ver}", pkg=full_name, ver=version)
                decision = cached
                decision = decision.model_copy(update={"mode": self._settings.decision_mode})
                return await self._apply_decision_and_respond(
                    full_name, version, decision, tarball_content, tarball_filename, str(request.url.path)
                )

        # Extract install scripts and scan
        tmp_dir = None
        try:
            artifacts, tmp_dir = extract_npm_install_scripts(tarball_content)

            # Build PackageInfo
            install_scripts: dict[str, str] = {}
            if version_meta:
                install_scripts = version_meta.install_scripts

            # Also parse from extracted package.json as fallback
            for art in artifacts:
                if art.name == "package.json":
                    install_scripts = install_scripts or parse_install_scripts(art)
                    break

            # Enrich metadata for maintainer/dependency scanners
            scan_metadata: dict = {}
            if version_meta:
                scan_metadata = {
                    "maintainers": version_meta.maintainers,
                    "dependencies": version_meta.dependencies,
                    "_npmUser": version_meta.npm_user,
                    "version_times": version_meta.version_times,
                }

            package_info = PackageInfo(
                name=full_name,
                version=version,
                registry="npm",
                publish_date=version_meta.publish_date if version_meta else None,
                install_scripts=install_scripts,
                metadata=scan_metadata,
            )

            # Run scan pipeline (tiered or classic)
            if isinstance(self._pipeline, TieredScanPipeline):
                has_hooks = detect_install_hooks("npm", "", artifacts, install_scripts)
                tiered = await self._pipeline.run(package_info, artifacts, has_install_hooks=has_hooks)
                all_results = tiered.fast_results + tiered.slow_results
                decision = self._engine.decide(all_results)
                decision = decision.model_copy(update={"llm_deferred": tiered.llm_deferred})

                if tiered.llm_deferred and self._bg_manager:
                    self._bg_manager.schedule(
                        "npm", package_info, artifacts, tmp_dir, content_hash, tiered.fast_results
                    )
                    tmp_dir = None  # ownership transferred
                elif self._cache:
                    await self._cache.put("npm", full_name, version, content_hash, decision)
            else:
                scan_results = await self._pipeline.run(package_info, artifacts)
                decision = self._engine.decide(scan_results)
                if self._cache:
                    await self._cache.put("npm", full_name, version, content_hash, decision)

        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return await self._apply_decision_and_respond(
            full_name, version, decision, tarball_content, tarball_filename, str(request.url.path)
        )

    async def _apply_decision_and_respond(
        self,
        full_name: str,
        version: str,
        decision: DecisionResult,
        tarball_content: bytes,
        tarball_filename: str,
        request_path: str,
    ) -> Response:
        """Log decision, enforce if needed, return tarball response."""

        deferred_tag = " [LLM deferred]" if decision.llm_deferred else ""
        logger.info(
            "Decision for {pkg}@{ver}: {verdict} (score={score:.4f}, mode={mode}){tag}",
            pkg=full_name,
            ver=version,
            verdict=decision.verdict,
            score=decision.final_score,
            mode=decision.mode,
            tag=deferred_tag,
        )

        # Metrics
        increment("scans_total")
        increment(f"scan_{decision.verdict}")

        # Audit log
        if self._audit:
            await self._audit.log_decision("npm", full_name, version, decision, request_path)

        # Notifications
        if self._notifications:
            await self._notifications.notify_decision("npm", full_name, version, decision)

        # Act on decision
        if decision.verdict == "deny" and decision.mode == "enforce":
            raise PackageBlockedError(
                package_name=full_name,
                version=version,
                reason=decision.reason,
            )

        if decision.verdict in ("deny", "quarantine"):
            logger.warning(
                "⚠ {verdict} for {pkg}@{ver}: {reason}",
                verdict=decision.verdict.upper(),
                pkg=full_name,
                ver=version,
                reason=decision.reason,
            )

        return Response(
            content=tarball_content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{tarball_filename}"'},
        )

    def _get_proxy_base_url(self, request: Request) -> str:
        """Derive proxy base URL from the incoming request."""
        return f"{request.url.scheme}://{request.url.netloc}"

    def _rewrite_tarball_urls(self, metadata: dict, proxy_base: str) -> dict:
        """Rewrite dist.tarball URLs in all versions to route through proxy."""
        versions = metadata.get("versions", {})
        for ver_data in versions.values():
            dist = ver_data.get("dist", {})
            original_url = dist.get("tarball", "")
            if original_url:
                parsed = urlparse(original_url)
                dist["tarball"] = f"{proxy_base}{parsed.path}"
        return metadata

    @staticmethod
    def _extract_version_from_tarball(package_name: str, filename: str) -> str:
        """Extract version from tarball filename like 'express-4.18.2.tgz'."""
        # Remove .tgz extension
        base = filename.removesuffix(".tgz")
        # Remove package name prefix (handle scoped pkg names)
        prefix = f"{package_name}-"
        if base.startswith(prefix):
            return base[len(prefix) :]
        # Fallback: take everything after last hyphen before version-like pattern
        parts = base.rsplit("-", 1)
        return parts[-1] if len(parts) > 1 else base

    def _build_upstream_tarball_url(self, full_name: str, tarball_filename: str) -> str:
        """Build the full upstream URL for a tarball."""
        return f"{self._registry.upstream_url}/{full_name}/-/{tarball_filename}"


def _json_bytes(data: dict) -> bytes:
    """Serialize dict to JSON bytes efficiently."""
    import json

    return json.dumps(data, separators=(",", ":")).encode()
