"""FastAPI application assembly."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from loguru import logger

from app.api.routers.audit import router as audit_router
from app.api.routers.cache import router as cache_router
from app.api.routers.config import router as config_router
from app.api.routers.dashboard import router as dashboard_router
from app.api.routers.health import router as health_router
from app.api.routers.metrics import router as metrics_router
from app.api.routers.sbom import router as sbom_router
from app.core.config import Settings, get_settings
from app.core.exception_handlers import (
    package_blocked_handler,
    package_not_found_handler,
    scan_timeout_handler,
    upstream_error_handler,
)
from app.core.exceptions import (
    PackageBlockedError,
    PackageNotFoundError,
    ScanTimeoutError,
    UpstreamRegistryError,
)
from app.core.logging import setup_logging
from app.core.version import VERSION
from app.db.audit_service import AuditService
from app.db.cache_service import CacheService
from app.db.session import Database
from app.decision.engine import DecisionEngine
from app.notifications import NotificationService
from app.proxy.middleware import RequestLoggingMiddleware
from app.proxy.npm import NpmProxy
from app.proxy.pypi import PyPIProxy
from app.proxy.rubygems import RubyGemsProxy
from app.registry.depsdev_client import DepsDevClient
from app.registry.npm_client import NpmRegistryClient
from app.registry.pypi_client import PyPIRegistryClient
from app.registry.rubygems_client import RubyGemsRegistryClient
from app.scanners.advisory_scanner import AdvisoryScanner
from app.scanners.ast_scanner import ASTScanner
from app.scanners.background import BackgroundScanManager
from app.scanners.base import TieredScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.heuristics_scanner import HeuristicsScanner
from app.scanners.ioc_checker import IOCScanner
from app.scanners.maintainer_scanner import MaintainerScanner
from app.scanners.metadata_scanner import MetadataScanner
from app.scanners.static_analysis import StaticAnalysisScanner
from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
from app.scanners.yara_scanner import YARAScanner


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    settings = get_settings()
    setup_logging(settings)

    logger.info("Starting Guard Proxy v{version}", version=VERSION)
    logger.info("Mode: {mode}", mode=settings.decision_mode)
    logger.info("npm upstream: {url}", url=settings.npm_upstream_url)
    logger.info("PyPI upstream: {url}", url=settings.pypi_upstream_url)
    logger.info("RubyGems upstream: {url}", url=settings.rubygems_upstream_url)

    # Database
    database = Database(settings)
    await database.create_tables()

    cache_service = CacheService(settings, database)
    audit_service = AuditService(database)

    # Decision engine (shared)
    decision_engine = DecisionEngine(settings)

    # LLM scanner (shared if enabled)
    llm_scanner = None
    if settings.llm_enabled:
        from app.scanners.llm.judge import LLMJudgeScanner

        llm_scanner = LLMJudgeScanner(settings)

    # Shared scanners
    ioc_scanner = IOCScanner()
    advisory_scanner = AdvisoryScanner(database)
    metadata_scanner = MetadataScanner() if settings.typosquatting_enabled else None
    heuristics_scanner = HeuristicsScanner() if settings.heuristics_enabled else None
    ast_scanner = ASTScanner() if settings.ast_analysis_enabled else None
    yara_scanner = YARAScanner(settings.yara_rules_path or None) if settings.yara_enabled else None
    maintainer_scanner = MaintainerScanner(database) if settings.maintainer_check_enabled else None
    depsdev_client = DepsDevClient(timeout=settings.depsdev_timeout)
    dependency_scanner = DependencyScanner(depsdev_client, settings) if settings.dependency_check_enabled else None

    # Advisory sync (background)
    advisory_sync = None
    if settings.advisory_sync_enabled:
        from app.db.advisory_sync import AdvisorySyncService

        advisory_sync = AdvisorySyncService(database, settings.advisory_sync_interval_hours)
        await advisory_sync.start()

    # Background scan manager (for deferred slow-tier scans: dependency + LLM)
    slow_bg_scanners = []
    if dependency_scanner:
        slow_bg_scanners.append(dependency_scanner)
    if llm_scanner:
        slow_bg_scanners.append(llm_scanner)

    bg_manager = None
    if slow_bg_scanners:
        bg_manager = BackgroundScanManager(
            slow_scanners=slow_bg_scanners,
            decision_engine=decision_engine,
            cache_service=cache_service,
            audit_service=audit_service,
        )

    def _build_fast_scanners(static_scanner):  # noqa: ANN001
        """Build fast tier scanner list (no network calls, <1s)."""
        scanners = [ioc_scanner, advisory_scanner, CooldownScanner(settings)]
        if metadata_scanner:
            scanners.append(metadata_scanner)
        if maintainer_scanner:
            scanners.append(maintainer_scanner)
        if settings.static_analysis_enabled:
            scanners.append(static_scanner)
        if heuristics_scanner:
            scanners.append(heuristics_scanner)
        if ast_scanner:
            scanners.append(ast_scanner)
        if yara_scanner:
            scanners.append(yara_scanner)
        return scanners

    def _build_slow_scanners():
        """Build slow tier scanner list (network-dependent, may be deferred)."""
        slow = []
        if dependency_scanner:
            slow.append(dependency_scanner)
        if llm_scanner:
            slow.append(llm_scanner)
        return slow

    # Notification service
    notification_service = NotificationService(settings.slack_webhook_url) if settings.slack_webhook_url else None
    if notification_service:
        logger.info("Slack notifications enabled")

    # --- npm proxy (tiered pipeline) ---
    npm_registry = NpmRegistryClient(settings)
    npm_fast = _build_fast_scanners(StaticAnalysisScanner(settings))
    npm_slow = _build_slow_scanners()
    npm_pipeline = TieredScanPipeline(npm_fast, npm_slow)
    npm_proxy = NpmProxy(
        settings,
        npm_registry,
        npm_pipeline,
        decision_engine,
        cache_service,
        audit_service,
        bg_manager,
        notification_service,
    )

    # --- PyPI proxy (tiered pipeline) ---
    pypi_registry = PyPIRegistryClient(settings)
    pypi_fast = _build_fast_scanners(PyPIStaticAnalysisScanner(settings))
    pypi_slow = _build_slow_scanners()
    pypi_pipeline = TieredScanPipeline(pypi_fast, pypi_slow)
    pypi_proxy = PyPIProxy(
        settings,
        pypi_registry,
        pypi_pipeline,
        decision_engine,
        cache_service,
        audit_service,
        bg_manager,
        notification_service,
    )

    # --- RubyGems proxy (tiered pipeline) ---
    rubygems_registry = RubyGemsRegistryClient(settings)
    rubygems_fast = _build_fast_scanners(RubyGemsStaticAnalysisScanner(settings))
    rubygems_slow = _build_slow_scanners()
    rubygems_pipeline = TieredScanPipeline(rubygems_fast, rubygems_slow)
    rubygems_proxy = RubyGemsProxy(
        settings,
        rubygems_registry,
        rubygems_pipeline,
        decision_engine,
        cache_service,
        audit_service,
        bg_manager,
        notification_service,
    )

    if llm_scanner:
        logger.info("LLM Judge enabled — tiered scanning active")
    fast_scanners_list = [
        ioc_scanner,
        advisory_scanner,
        True,  # CooldownScanner (always active, created per-registry in _build_fast_scanners)
        metadata_scanner,
        maintainer_scanner,
        True if settings.static_analysis_enabled else None,  # StaticAnalysis (per-registry)
        heuristics_scanner,
        ast_scanner,
        yara_scanner,
    ]
    scanner_count = sum(1 for s in fast_scanners_list if s)
    logger.info("Fast tier: {n} scanners active", n=scanner_count)

    # Mount routers — admin first, then proxies
    app.include_router(health_router)
    app.include_router(dashboard_router)
    app.include_router(metrics_router)
    app.include_router(sbom_router)
    app.include_router(cache_router)
    app.include_router(config_router)
    app.include_router(audit_router)
    app.include_router(rubygems_proxy.get_router())
    app.include_router(pypi_proxy.get_router())
    app.include_router(npm_proxy.get_router())

    # Store services on app state for API access
    app.state.cache_service = cache_service
    app.state.audit_service = audit_service
    app.state.settings = settings
    app.state.bg_manager = bg_manager

    logger.info("Guard Proxy ready — listening for npm, PyPI, and RubyGems requests")
    yield

    # Shutdown
    if advisory_sync:
        await advisory_sync.stop()
    if bg_manager:
        await bg_manager.shutdown()
    await depsdev_client.close()
    await npm_registry.close()
    await pypi_registry.close()
    await rubygems_registry.close()
    await database.close()
    logger.info("Guard Proxy shut down")


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="Guard Proxy",
        version=VERSION,
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Exception handlers
    app.add_exception_handler(PackageBlockedError, package_blocked_handler)  # type: ignore[arg-type]
    app.add_exception_handler(PackageNotFoundError, package_not_found_handler)  # type: ignore[arg-type]
    app.add_exception_handler(UpstreamRegistryError, upstream_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(ScanTimeoutError, scan_timeout_handler)  # type: ignore[arg-type]

    return app
