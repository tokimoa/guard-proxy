"""Application configuration via pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "Guard Proxy"
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    log_format: Literal["text", "json"] = "text"

    # Proxy
    npm_proxy_port: int = 4873
    npm_upstream_url: str = "https://registry.npmjs.org"
    pypi_proxy_port: int = 4874
    pypi_upstream_url: str = "https://pypi.org"
    rubygems_proxy_port: int = 4875
    rubygems_upstream_url: str = "https://rubygems.org"
    go_proxy_port: int = 4876
    go_upstream_url: str = "https://proxy.golang.org"
    cargo_proxy_port: int = 4877
    cargo_upstream_url: str = "https://crates.io"
    admin_api_port: int = 8100

    # Cooldown gate
    cooldown_days: int = 7
    cooldown_action: Literal["warn", "deny"] = "warn"

    # Static analysis
    static_analysis_enabled: bool = True
    static_analysis_severity_threshold: Literal["low", "medium", "high", "critical"] = "medium"

    # LLM Judge (disabled in Phase 1)
    llm_enabled: bool = False
    llm_strategy: Literal["local_first", "cloud_only", "local_only", "consensus"] = "local_first"
    llm_max_tokens: int = 4096
    llm_max_file_size_kb: int = 512

    # Escalation
    local_confidence_threshold: float = 0.8
    obfuscation_cloud_threshold: float = 0.7

    # Ollama
    ollama_enabled: bool = True
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3.5:9b"
    ollama_timeout_seconds: int = 60

    # Anthropic
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    anthropic_timeout_seconds: int = 30

    # OpenAI
    openai_api_key: str = ""
    openai_model: str = "gpt-5.4"
    openai_timeout_seconds: int = 30

    # Custom LLM
    custom_llm_base_url: str = ""
    custom_llm_api_key: str = ""
    custom_llm_model: str = ""

    # Cost control
    cloud_daily_limit: int = 100
    cloud_monthly_budget_usd: float = 20.0

    # Decision engine
    decision_mode: Literal["warn", "enforce"] = "warn"
    warn_threshold: float = 0.3
    deny_threshold: float = 0.7
    cooldown_weight: float = 0.3
    static_analysis_weight: float = 0.4
    llm_weight: float = 0.3

    # Cache
    cache_db_path: str = "./data/cache.db"
    cache_ttl_hours: int = 168
    cache_max_size_mb: int = 500

    # Database
    db_path: str = "./data/guard_proxy.db"

    # Notifications
    slack_webhook_url: str = ""

    # Advisory sync
    advisory_sync_enabled: bool = True
    advisory_sync_interval_hours: int = 6

    # Metadata scanner
    typosquatting_enabled: bool = True

    # Heuristics scanner
    heuristics_enabled: bool = True

    # AST analysis
    ast_analysis_enabled: bool = True

    # YARA rules
    yara_enabled: bool = True
    yara_rules_path: str = ""

    # SBOM
    sbom_enabled: bool = True

    # Maintainer verification
    maintainer_check_enabled: bool = True

    # Dependency graph analysis
    dependency_check_enabled: bool = True
    depsdev_timeout: float = 2.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
