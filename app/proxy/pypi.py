"""PyPI registry proxy with security scanning."""

import re
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
from app.registry.pypi_client import PyPIRegistryClient
from app.scanners.background import BackgroundScanManager
from app.scanners.base import ScanPipeline, TieredScanPipeline
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.utils.hash import compute_sha256
from app.utils.install_hooks import detect_install_hooks
from app.utils.tarball import extract_pypi_install_scripts

# Match package filenames like: requests-2.31.0-py3-none-any.whl, requests-2.31.0.tar.gz
_VERSION_PATTERN = re.compile(r"^(.+?)-(\d+\..+?)(?:-|\.tar\.gz|\.zip|\.whl)")


class PyPIProxy:
    """PyPI transparent proxy with package interception and scanning."""

    # Default PyPI file hosts — extended dynamically with upstream_url host
    _DEFAULT_FILE_HOSTS = {"files.pythonhosted.org", "pypi.org", "pypi.io"}

    def __init__(
        self,
        settings: Settings,
        registry_client: PyPIRegistryClient,
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
        self._files_base_url = self._derive_files_base_url()

    def get_router(self) -> APIRouter:
        router = APIRouter()

        # Simple index root: GET /simple/
        router.add_api_route("/simple/", self.handle_simple_root, methods=["GET"])
        # Simple package index: GET /simple/<package>/
        router.add_api_route("/simple/{package_name}/", self.handle_simple_index, methods=["GET"])
        # Package download: GET /packages/<path>
        router.add_api_route(
            "/packages/{file_path:path}",
            self.handle_package_download,
            methods=["GET"],
        )

        return router

    async def handle_simple_root(self, request: Request) -> Response:
        """Forward the simple index root."""
        try:
            resp = await self._registry.get("/simple/")
            return Response(content=resp.content, media_type=resp.headers.get("content-type", "text/html"))
        except Exception as e:
            logger.error("Failed to fetch simple index root: {err}", err=str(e))
            return Response(content="Upstream error", status_code=502)

    def _derive_files_base_url(self) -> str:
        """Derive the base URL for file downloads from upstream config.

        For official PyPI (pypi.org), files are at files.pythonhosted.org.
        For private mirrors, files are typically served from the same host.
        """
        upstream = self._registry.upstream_url
        parsed = urlparse(upstream)
        if parsed.hostname in ("pypi.org", "pypi.io"):
            return "https://files.pythonhosted.org"
        return upstream

    async def handle_simple_index(self, request: Request, package_name: str) -> Response:
        """Serve PEP 503 simple index with rewritten download URLs."""
        html = await self._registry.get_simple_index(package_name)

        # Rewrite download URLs to route through this proxy
        proxy_base = f"{request.url.scheme}://{request.url.netloc}"
        upstream_host = urlparse(self._registry.upstream_url).hostname
        rewrite_hosts = self._DEFAULT_FILE_HOSTS | ({upstream_host} if upstream_host else set())
        html = self._rewrite_download_urls(html, proxy_base, rewrite_hosts)

        return Response(content=html, media_type="text/html")

    async def handle_package_download(self, request: Request, file_path: str) -> Response:
        """Intercept package download, scan, then allow or block."""
        filename = file_path.split("/")[-1]

        # .metadata files are just metadata — pass through without scanning
        if filename.endswith(".metadata"):
            upstream_url = f"{self._files_base_url}/packages/{file_path}"
            content = await self._registry.download_artifact(upstream_url)
            return Response(content=content, media_type="application/octet-stream")

        pkg_name, version = self._extract_name_version(filename)

        logger.info("PyPI download: {pkg}@{ver} ({file})", pkg=pkg_name, ver=version, file=filename)

        # Download from upstream
        upstream_url = f"{self._files_base_url}/packages/{file_path}"
        content = await self._registry.download_artifact(upstream_url)

        # Check cache
        content_hash = compute_sha256(content)
        if self._cache:
            cached = await self._cache.get("pypi", pkg_name, version, content_hash)
            if cached is not None:
                logger.info("Cache hit for {pkg}@{ver}", pkg=pkg_name, ver=version)
                decision = cached.model_copy(update={"mode": self._settings.decision_mode})
                return await self._apply_decision(pkg_name, version, decision, content, filename, str(request.url.path))

        # Extract and scan
        tmp_dir = None
        try:
            artifacts, tmp_dir = extract_pypi_install_scripts(content, filename)

            # Fetch publish date and metadata for scanners
            publish_date = None
            scan_metadata: dict = {}
            try:
                meta = await self._registry.get_version_metadata(pkg_name, version)
                publish_date = PyPIRegistryClient.extract_publish_date(meta)
                info = meta.get("info", {})
                scan_metadata = {
                    "author": info.get("author", ""),
                    "author_email": info.get("author_email", ""),
                    "maintainer": info.get("maintainer", ""),
                    "requires_dist": info.get("requires_dist") or [],
                }
            except Exception:
                logger.warning(
                    "Could not fetch metadata for {pkg}@{ver}, proceeding with scan",
                    pkg=pkg_name,
                    ver=version,
                )

            package_info = PackageInfo(
                name=pkg_name,
                version=version,
                registry="pypi",
                publish_date=publish_date,
                metadata=scan_metadata,
            )

            # Tiered or classic pipeline
            if isinstance(self._pipeline, TieredScanPipeline):
                has_hooks = detect_install_hooks("pypi", filename, artifacts, {})
                tiered = await self._pipeline.run(package_info, artifacts, has_install_hooks=has_hooks)
                all_results = tiered.fast_results + tiered.slow_results
                decision = self._engine.decide(all_results)
                decision = decision.model_copy(update={"llm_deferred": tiered.llm_deferred})

                if tiered.llm_deferred and self._bg_manager:
                    self._bg_manager.schedule(
                        "pypi", package_info, artifacts, tmp_dir, content_hash, tiered.fast_results
                    )
                    tmp_dir = None  # ownership transferred to bg manager
                elif self._cache:
                    await self._cache.put("pypi", pkg_name, version, content_hash, decision)
            else:
                scan_results = await self._pipeline.run(package_info, artifacts)
                decision = self._engine.decide(scan_results)
                if self._cache:
                    await self._cache.put("pypi", pkg_name, version, content_hash, decision)
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        return await self._apply_decision(pkg_name, version, decision, content, filename, str(request.url.path))

    async def _apply_decision(
        self,
        pkg_name: str,
        version: str,
        decision: DecisionResult,
        content: bytes,
        filename: str,
        request_path: str,
    ) -> Response:
        deferred_tag = " [LLM deferred]" if decision.llm_deferred else ""
        logger.info(
            "Decision for {pkg}@{ver}: {verdict} (score={score:.4f}, mode={mode}){tag}",
            pkg=pkg_name,
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
            await self._audit.log_decision("pypi", pkg_name, version, decision, request_path)

        # Notifications
        if self._notifications:
            await self._notifications.notify_decision("pypi", pkg_name, version, decision)

        if decision.verdict == "deny" and decision.mode == "enforce":
            raise PackageBlockedError(package_name=pkg_name, version=version, reason=decision.reason)

        if decision.verdict in ("deny", "quarantine"):
            logger.warning(
                "PyPI {verdict} for {pkg}@{ver}",
                verdict=decision.verdict.upper(),
                pkg=pkg_name,
                ver=version,
            )

        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @staticmethod
    def _rewrite_download_urls(html: str, proxy_base: str, rewrite_hosts: set[str]) -> str:
        """Rewrite absolute PyPI download URLs in simple index HTML."""

        def _rewrite(match: re.Match) -> str:
            url = match.group(1)
            parsed = urlparse(url)
            if parsed.scheme and parsed.hostname in rewrite_hosts:
                return f'href="{proxy_base}{parsed.path}"'
            return match.group(0)

        return re.sub(r'href="([^"]+)"', _rewrite, html)

    @staticmethod
    def _extract_name_version(filename: str) -> tuple[str, str]:
        """Extract package name and version from filename."""
        m = _VERSION_PATTERN.match(filename)
        if m:
            return m.group(1).replace("_", "-").lower(), m.group(2)
        # Fallback
        base = filename.removesuffix(".tar.gz").removesuffix(".zip").removesuffix(".whl")
        parts = base.rsplit("-", 1)
        if len(parts) == 2:
            return parts[0].replace("_", "-").lower(), parts[1]
        return base.lower(), "unknown"
