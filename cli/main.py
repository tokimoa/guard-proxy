"""Guard Proxy CLI entry point."""

import asyncio

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from app.core.config import get_settings
from app.core.version import VERSION

app = typer.Typer(
    name="guard-proxy",
    help="Security proxy for npm/PyPI/RubyGems/Go/Cargo — protect developers from supply chain attacks.",
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Manage YARA rule sources and updates.")
app.add_typer(rules_app, name="rules")
console = Console()


@app.command()
def start(
    host: str = typer.Option("127.0.0.1", help="Bind host (use 0.0.0.0 for network access)"),
    port: int = typer.Option(None, help="Bind port (default: from config)"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development"),
) -> None:
    """Start the Guard Proxy server."""
    settings = get_settings()
    bind_port = port or settings.npm_proxy_port

    console.print(f"[bold green]Guard Proxy v{VERSION}[/bold green]")
    console.print(f"  Mode: {settings.decision_mode}")
    console.print(f"  Listening: {host}:{bind_port}")
    console.print("  Single-port routes: /npm, /pypi, /gems, /go, /cargo")
    console.print(f"  Dashboard: http://{host}:{bind_port}/dashboard")

    uvicorn.run(
        "app.main:create_app",
        host=host,
        port=bind_port,
        reload=reload,
        factory=True,
        log_level="warning",
    )


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"Guard Proxy v{VERSION}")


@app.command(name="sbom")
def sbom_export(
    file: str = typer.Option("", help="Output file (default: stdout)"),
) -> None:
    """Export SBOM for recently scanned packages."""
    import asyncio
    import json

    from app.db.audit_service import AuditService
    from app.db.session import Database

    settings = get_settings()

    async def _export() -> str:
        db = Database(settings)
        await db.create_tables()
        audit = AuditService(db)
        entries = await audit.recent(limit=50)

        components = []
        for e in entries:
            components.append(
                {
                    "type": "library",
                    "name": e["package"],
                    "version": e["version"],
                    "purl": f"pkg:{e['registry']}/{e['package']}@{e['version']}",
                    "properties": [
                        {"name": "guard-proxy:verdict", "value": e["action"]},
                        {"name": "guard-proxy:score", "value": str(e["score"])},
                    ],
                }
            )
        await db.close()

        from datetime import UTC, datetime

        from app.core.version import VERSION

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": {"components": [{"type": "application", "name": "guard-proxy", "version": VERSION}]},
            },
            "components": components,
        }
        return json.dumps(sbom, indent=2)

    result = asyncio.run(_export())

    if file:
        from pathlib import Path

        Path(file).write_text(result)
        console.print(f"SBOM exported to [bold]{file}[/bold]")
    else:
        console.print(result)


@app.command(name="sync-ioc")
def sync_ioc() -> None:
    """Sync IOC database from DataDog malicious-software-packages-dataset."""
    import asyncio
    from pathlib import Path

    from app.db.datadog_sync import sync_datadog_to_file

    ioc_path = str(Path(__file__).resolve().parent.parent / "data" / "known_malicious.json")
    console.print("Syncing IOC database from DataDog dataset...")

    async def _sync() -> None:
        data = await sync_datadog_to_file(ioc_path)
        malicious = data.get("malicious_packages", {})
        for eco, entries in sorted(malicious.items()):
            console.print(f"  {eco}: [bold]{len(entries)}[/bold] malicious packages")
        total = sum(len(v) for v in malicious.values())
        console.print(f"\n  [green]Total: {total} malicious packages synced[/green]")

        # Show high-impact alerts
        alerts = data.get("_high_impact_alerts", [])
        if alerts:
            console.print(f"\n  [bold red]⚠ {len(alerts)} HIGH-IMPACT alerts:[/bold red]")
            for a in alerts:
                console.print(
                    f"    [red]{a['severity']}[/red]: {a['ecosystem']}/{a['name']} "
                    f"({a['weekly_downloads']:,} downloads/week)"
                )

    asyncio.run(_sync())


@app.command()
def config() -> None:
    """Show current configuration."""
    settings = get_settings()
    data = settings.model_dump()

    table = Table(title="Guard Proxy Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # Redact secrets
    secret_keys = ("anthropic_api_key", "openai_api_key", "custom_llm_api_key", "slack_webhook_url")
    for key in secret_keys:
        val = data.get(key, "")
        if val:
            data[key] = "****"

    for key, val in sorted(data.items()):
        table.add_row(key, str(val))

    console.print(table)


@app.command()
def status() -> None:
    """Show proxy status and cache stats."""
    settings = get_settings()

    console.print(f"[bold]Guard Proxy v{VERSION}[/bold]")
    console.print(f"  Mode: {settings.decision_mode}")
    console.print(f"  Cooldown: {settings.cooldown_days} days ({settings.cooldown_action})")
    console.print(f"  Static Analysis: {'enabled' if settings.static_analysis_enabled else 'disabled'}")
    console.print(f"  LLM Judge: {'enabled' if settings.llm_enabled else 'disabled'}")

    if settings.llm_enabled:
        console.print(f"  LLM Strategy: {settings.llm_strategy}")

    # Try to show cache stats
    try:
        from app.db.cache_service import CacheService
        from app.db.session import Database

        async def _get_stats() -> dict:
            db = Database(settings)
            svc = CacheService(settings, db)
            stats = await svc.stats()
            await db.close()
            return stats

        stats = asyncio.run(_get_stats())
        console.print("\n[bold]Cache:[/bold]")
        console.print(f"  Active entries: {stats['active_entries']}")
        console.print(f"  Expired entries: {stats['expired_entries']}")
    except Exception:
        console.print("\n  [dim]Cache: not initialized[/dim]")


@app.command()
def scan(
    package: str = typer.Argument(help="Package name (e.g., 'express' or 'flask@3.1.1')"),
    registry: str = typer.Option("npm", help="Registry: npm or pypi"),
) -> None:
    """Manually scan a package."""
    # Handle scoped packages: @scope/pkg@1.0.0 → name=@scope/pkg, ver=1.0.0
    if package.startswith("@") and package.count("@") >= 2:
        name, ver = package.rsplit("@", 1)
    elif "@" in package and not package.startswith("@"):
        name, ver = package.rsplit("@", 1)
    else:
        name = package
        ver = "latest"

    console.print(f"Scanning [bold]{name}@{ver}[/bold] ({registry})...")

    async def _scan() -> None:
        settings = get_settings()

        if registry == "pypi":
            await _scan_pypi(settings, name, ver)
        elif registry == "rubygems":
            await _scan_rubygems(settings, name, ver)
        else:
            await _scan_npm(settings, name, ver)

    async def _scan_npm(settings, name: str, ver: str) -> None:
        import shutil

        from app.decision.engine import DecisionEngine
        from app.registry.npm_client import NpmRegistryClient
        from app.scanners.base import ScanPipeline
        from app.scanners.cooldown import CooldownScanner
        from app.scanners.ioc_checker import IOCScanner
        from app.scanners.static_analysis import StaticAnalysisScanner
        from app.schemas.package import PackageInfo
        from app.utils.tarball import extract_npm_install_scripts, parse_install_scripts

        client = NpmRegistryClient(settings)
        try:
            if ver == "latest":
                metadata = await client.get_package_metadata(name)
                resolved_ver = metadata.get("dist-tags", {}).get("latest", "")
                if not resolved_ver:
                    console.print("[red]Could not resolve latest version[/red]")
                    return
            else:
                resolved_ver = ver

            console.print(f"  Version: {resolved_ver}")
            version_meta = await client.get_version_metadata(name, resolved_ver)
            if not version_meta.dist:
                console.print("[red]No dist info found[/red]")
                return

            tarball = await client.download_tarball(version_meta.dist.tarball)
            artifacts, tmp_dir = extract_npm_install_scripts(tarball)
            try:
                install_scripts = version_meta.install_scripts
                for art in artifacts:
                    if art.name == "package.json":
                        install_scripts = install_scripts or parse_install_scripts(art)
                        break

                pkg_info = PackageInfo(
                    name=name,
                    version=resolved_ver,
                    registry="npm",
                    publish_date=version_meta.publish_date,
                    install_scripts=install_scripts,
                )
                scanners = [IOCScanner(), CooldownScanner(settings)]
                if settings.static_analysis_enabled:
                    scanners.append(StaticAnalysisScanner(settings))
                await _async_run_and_display(ScanPipeline(scanners), DecisionEngine(settings), pkg_info, artifacts)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        finally:
            await client.close()

    async def _scan_pypi(settings, name: str, ver: str) -> None:  # noqa: ANN001
        import shutil

        from app.decision.engine import DecisionEngine
        from app.registry.pypi_client import PyPIRegistryClient
        from app.scanners.base import ScanPipeline
        from app.scanners.cooldown import CooldownScanner
        from app.scanners.ioc_checker import IOCScanner
        from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner
        from app.schemas.package import PackageInfo
        from app.utils.tarball import extract_pypi_install_scripts

        client = PyPIRegistryClient(settings)
        try:
            if ver == "latest":
                metadata = await client.get_package_metadata(name)
                resolved_ver = metadata.get("info", {}).get("version", "")
                if not resolved_ver:
                    console.print("[red]Could not resolve latest version[/red]")
                    return
            else:
                resolved_ver = ver

            console.print(f"  Version: {resolved_ver}")

            meta = await client.get_version_metadata(name, resolved_ver)
            publish_date = PyPIRegistryClient.extract_publish_date(meta)

            # Find a wheel or sdist to download
            urls = meta.get("urls", [])
            download_url = None
            download_filename = ""
            for u in urls:
                if u.get("packagetype") == "bdist_wheel":
                    download_url = u["url"]
                    download_filename = u["filename"]
                    break
            if not download_url:
                for u in urls:
                    if u.get("packagetype") == "sdist":
                        download_url = u["url"]
                        download_filename = u["filename"]
                        break
            if not download_url:
                console.print("[red]No downloadable artifact found[/red]")
                return

            console.print(f"  Artifact: {download_filename}")
            content = await client.download_artifact(download_url)
            artifacts, tmp_dir = extract_pypi_install_scripts(content, download_filename)
            try:
                pkg_info = PackageInfo(
                    name=name,
                    version=resolved_ver,
                    registry="pypi",
                    publish_date=publish_date,
                )
                scanners = [IOCScanner(), CooldownScanner(settings)]
                if settings.static_analysis_enabled:
                    scanners.append(PyPIStaticAnalysisScanner(settings))
                await _async_run_and_display(ScanPipeline(scanners), DecisionEngine(settings), pkg_info, artifacts)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        finally:
            await client.close()

    async def _scan_rubygems(settings, name: str, ver: str) -> None:  # noqa: ANN001
        import shutil

        from app.decision.engine import DecisionEngine
        from app.registry.rubygems_client import RubyGemsRegistryClient
        from app.scanners.base import ScanPipeline
        from app.scanners.cooldown import CooldownScanner
        from app.scanners.ioc_checker import IOCScanner
        from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
        from app.schemas.package import PackageInfo
        from app.utils.tarball import extract_gem_files

        client = RubyGemsRegistryClient(settings)
        try:
            if ver == "latest":
                metadata = await client.get_gem_metadata(name)
                resolved_ver = metadata.get("version", "")
                if not resolved_ver:
                    console.print("[red]Could not resolve latest version[/red]")
                    return
            else:
                resolved_ver = ver

            console.print(f"  Version: {resolved_ver}")

            gem_filename = f"{name}-{resolved_ver}.gem"
            console.print(f"  Artifact: {gem_filename}")
            gem_content = await client.download_gem(gem_filename)
            artifacts, tmp_dir = extract_gem_files(gem_content, gem_filename)
            try:
                publish_date = None
                try:
                    versions = await client.get_gem_versions(name)
                    publish_date = RubyGemsRegistryClient.extract_publish_date(versions, resolved_ver)
                except Exception:
                    pass

                pkg_info = PackageInfo(
                    name=name,
                    version=resolved_ver,
                    registry="rubygems",
                    publish_date=publish_date,
                )
                scanners = [IOCScanner(), CooldownScanner(settings)]
                if settings.static_analysis_enabled:
                    scanners.append(RubyGemsStaticAnalysisScanner(settings))
                await _async_run_and_display(ScanPipeline(scanners), DecisionEngine(settings), pkg_info, artifacts)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        finally:
            await client.close()

    asyncio.run(_scan())


async def _async_run_and_display(pipeline, engine, pkg_info, artifacts) -> None:  # noqa: ANN001
    """Run scan pipeline and display results."""
    results = await pipeline.run(pkg_info, artifacts)
    decision = engine.decide(results)

    verdict_colors = {"allow": "green", "quarantine": "yellow", "deny": "red"}
    color = verdict_colors.get(decision.verdict, "white")
    console.print(f"\n  Verdict: [{color}]{decision.verdict.upper()}[/{color}]")
    console.print(f"  Score: {decision.final_score:.4f}")
    console.print(f"  Mode: {decision.mode}")

    for r in decision.scan_results:
        v_color = {"pass": "green", "warn": "yellow", "fail": "red"}.get(r.verdict, "white")
        console.print(f"\n  [{v_color}][{r.scanner_name}][/{v_color}] {r.verdict} (confidence={r.confidence:.2f})")
        console.print(f"    {r.details[:200]}")


@rules_app.command(name="list")
def rules_list(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show individual rules"),
) -> None:
    """List installed YARA rule sources and rules."""
    from app.rules.manager import RuleManager

    manager = RuleManager()

    sources = manager.list_sources()
    if not sources:
        console.print("[dim]No rule sources installed.[/dim]")
        console.print("Add one with: guard-proxy rules add <name> <url>")
        return

    table = Table(title="YARA Rule Sources")
    table.add_column("Name", style="cyan")
    table.add_column("Rules", justify="right", style="green")
    table.add_column("Description")
    table.add_column("Updated", style="dim")
    table.add_column("SHA256", style="dim")

    for s in sources:
        updated = s["updated_at"][:10] if s["updated_at"] else "-"
        table.add_row(s["name"], str(s["rule_count"]), s["description"], updated, s["sha256"] or "-")

    console.print(table)
    console.print(f"\n  Total sources: {len(sources)}")

    if verbose:
        rules = manager.list_rules()
        if rules:
            console.print()
            rt = Table(title="Individual Rules")
            rt.add_column("Rule", style="cyan")
            rt.add_column("Severity", style="yellow")
            rt.add_column("Source File", style="dim")
            rt.add_column("Description")
            for r in rules:
                sev_color = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(r["severity"], "white")
                rt.add_row(r["name"], f"[{sev_color}]{r['severity']}[/{sev_color}]", r["source_file"], r["description"])
            console.print(rt)
            console.print(f"\n  Total rules: {len(rules)}")


@rules_app.command(name="update")
def rules_update(
    source_name: str = typer.Argument(None, help="Source name to update (default: all)"),
) -> None:
    """Fetch latest YARA rules from configured sources."""
    from app.rules.manager import RuleManager

    manager = RuleManager()

    async def _update() -> list[dict]:
        if source_name:
            result = await manager.update_source(source_name)
            return [result]
        return await manager.update_all()

    results = asyncio.run(_update())

    for r in results:
        status = r.get("status", "unknown")
        name = r.get("name", "?")
        if status == "updated":
            console.print(f"  [green]{name}[/green]: updated ({r['rule_count']} rules)")
        elif status == "unchanged":
            console.print(f"  [dim]{name}[/dim]: unchanged")
        elif status == "skipped":
            console.print(f"  [dim]{name}[/dim]: skipped ({r.get('reason', '')})")
        elif status == "error":
            console.print(f"  [red]{name}[/red]: error — {r.get('error', '')}")


@rules_app.command(name="add")
def rules_add(
    name: str = typer.Argument(help="Source name (e.g., 'guarddog-community')"),
    url: str = typer.Argument(help="URL to .yar file"),
    description: str = typer.Option("", help="Description of this rule source"),
) -> None:
    """Add a new YARA rule source."""
    from app.rules.manager import RuleManager

    manager = RuleManager()

    async def _add() -> dict:
        return await manager.add_source(name, url, description)

    try:
        result = asyncio.run(_add())
        console.print(f"  [green]Added '{name}'[/green]: {result['rule_count']} rules installed")
    except Exception as e:
        console.print(f"  [red]Error[/red]: {e}")


@rules_app.command(name="remove")
def rules_remove(
    name: str = typer.Argument(help="Source name to remove"),
) -> None:
    """Remove a YARA rule source."""
    from app.rules.manager import RuleManager

    manager = RuleManager()
    if manager.remove_source(name):
        console.print(f"  [green]Removed '{name}'[/green]")
    else:
        console.print(f"  [yellow]Source '{name}' not found[/yellow]")


if __name__ == "__main__":
    app()
