# Guard Proxy - Implementation Plan

> Japanese version: [IMPLEMENTATION_PLAN_ja.md](IMPLEMENTATION_PLAN_ja.md)

## Phase Overview

| Phase | Content | Key Deliverables | Status |
|---|---|---|---|
| Phase 1 | MVP: Cooldown + Static Analysis (npm only) | Working npm proxy | Complete |
| Phase 2 | Cache + CLI + Admin API | Developer UX | Complete |
| Phase 3 | LLM Judge: Multi-provider support | Local + cloud LLM judgment | Complete |
| Phase 4 | PyPI + RubyGems support | pip install / gem install protection | Complete |
| Phase 5 | Operations hardening | IOC, notifications, metrics, CI/CD | Complete |
| Phase 5.5 | Smart Two-Tier Scanning | LLM latency elimination, background scanning | Complete |

---

## Phase 1: MVP (Cooldown + Static Analysis / npm Only)

### Goal
Build a minimal proxy that can verify package safety during `npm install` and block dangerous packages.

### Tasks

#### 1-1. Project Initialization
- [x] Create `pyproject.toml` (dependency definitions, ruff config, pytest config)
- [x] Create `.env.example`
- [x] Create `.gitignore`
- [x] Create `.pre-commit-config.yaml`
- [x] Create `Taskfile.yml` (task definitions for lint, test, dev, etc.)
- [x] Create `.python-version` (3.12)
- [x] Set up uv environment (`uv sync`)

#### 1-2. Application Foundation (`app/core/`)
- [x] `config.py` -- Configuration management via pydantic-settings
- [x] `logging.py` -- loguru configuration
- [x] `version.py` -- Version definition
- [x] `exceptions.py` -- Custom exceptions (PackageBlockedError, ScanTimeoutError, etc.)
- [x] `exception_handlers.py` -- FastAPI exception handlers

#### 1-3. Schema Definitions (`app/schemas/`)
- [x] `package.py` -- PackageInfo, PackageMetadata
- [x] `scan.py` -- ScanRequest, ScanResult
- [x] `decision.py` -- DecisionResult (allow/deny/quarantine)

#### 1-4. Registry Client (`app/registry/`)
- [x] `npm_client.py` -- Fetch metadata from npm registry API
  - `GET https://registry.npmjs.org/<package>` -- All version metadata
  - `GET https://registry.npmjs.org/<package>/<version>` -- Specific version
  - Extract publish date, dependency list, dist info (tarball URL, shasum)

#### 1-5. Scanner Implementation (`app/scanners/`)
- [x] `base.py` -- ScannerProtocol definition
- [x] `cooldown.py` -- Cooldown gate
  - Calculate days elapsed since publish date
  - fail/warn if below COOLDOWN_DAYS
  - Suggest alternative versions that have passed cooldown
- [x] `static_analysis.py` -- Static analysis scanner
  - Extract install scripts from package.json
  - Pattern matching on script contents
- [x] `patterns/npm_patterns.py` -- npm detection pattern definitions
  - Credential access patterns
  - External communication patterns
  - Obfuscation patterns
  - Known malicious patterns (plain-crypto-js, etc.)

#### 1-6. Decision Engine (`app/decision/`)
- [x] `models.py` -- Decision result models
- [x] `engine.py` -- Weighted scoring logic
  - Receive and integrate ScanResults from each scanner
  - Threshold-based allow/quarantine/deny verdicts

#### 1-7. Utilities (`app/utils/`)
- [x] `tarball.py` -- Tarball extraction, install script file extraction
- [x] `hash.py` -- Package hash computation (for cache keys)

#### 1-8. npm Proxy (`app/proxy/`)
- [x] `base.py` -- Abstract proxy base class
- [x] `npm.py` -- npm proxy implementation
  - Relay metadata requests
  - Intercept tarball download requests
  - Extract tarball to temp directory -> scan -> relay/block
- [x] `middleware.py` -- Request logging

#### 1-9. Application Startup (`app/main.py`)
- [x] FastAPI app initialization
- [x] Proxy routing configuration
- [x] Lifespan (startup/shutdown)
- [x] Exception handler registration

#### 1-10. Tests
- [x] `tests/test_scanners/test_cooldown.py`
- [x] `tests/test_scanners/test_static_analysis.py`
- [x] `tests/test_decision/test_engine.py`
- [x] `tests/test_registry/test_npm_client.py`
- [x] `tests/test_proxy/test_npm.py`
- [x] `tests/conftest.py` -- Common fixtures

#### 1-11. Docker
- [x] `deployment/Dockerfile`
- [x] `deployment/docker-compose.yml`

### Completion Criteria
- [x] With `.npmrc` registry set, `npm install <package>` works correctly
- [x] Packages within the cooldown period are appropriately blocked/warned
- [x] Malicious postinstall patterns (base64+eval, etc.) are detected
- [x] Legitimate packages (node-gyp, etc.) do not trigger false positives

---

## Phase 2: Cache + CLI

### Goal
Speed up operations by caching scan results and provide a developer-facing CLI.

### Tasks

#### 2-1. Database (`app/db/`)
- [x] `session.py` -- SQLite session management (WAL mode enabled)
- [x] `models/scan_result.py` -- Scan result cache model
- [x] `models/audit_log.py` -- Audit log model
- [x] Migration scripts

#### 2-2. Cache Integration
- [x] Check cache before starting scan pipeline
- [x] Save to cache after scan completion
- [x] Cache key: `{registry}:{package_name}:{version}:{content_hash}`
- [x] TTL management (default 7 days)

#### 2-3. CLI (`cli/`)
- [x] `main.py` -- Typer entry point
- [x] `commands/start.py` -- `guard-proxy start`
- [x] `commands/scan.py` -- `guard-proxy scan <package>`
- [x] `commands/config.py` -- `guard-proxy config show/init`
- [x] `commands/cache.py` -- `guard-proxy cache list/clear/stats`
- [x] `output.py` -- Formatted output with Rich

#### 2-4. Admin API (`app/api/`)
- [x] `routers/health.py` -- Health check
- [x] `routers/scan.py` -- Manual scan API
- [x] `routers/cache.py` -- Cache management API

#### 2-5. Additional Tests
- [x] `tests/test_cli/test_commands.py`
- [x] Cache hit/miss tests

### Completion Criteria
- [x] Re-scanning the same package is accelerated via cache
- [x] `guard-proxy` CLI commands work
- [x] `guard-proxy scan axios@1.13.6` returns manual scan results

---

## Phase 3: LLM Judge -- Multi-Provider Support

### Goal
Build a flexible LLM judgment engine combining local LLM (Ollama) and cloud LLMs (Claude API / GPT API). Enable users to choose between cost and time investment.

### Tasks

#### 3-1. LLM Provider Abstraction (`app/scanners/llm/provider.py`)
- [x] `LLMProvider` Protocol definition
  ```python
  class LLMProvider(Protocol):
      async def judge(self, prompt: str, schema: dict) -> JudgeResult: ...
      async def is_available(self) -> bool: ...
      @property
      def provider_name(self) -> str: ...
  ```
- [x] `JudgeResult` model definition (verdict, reasons, confidence, suspicious_lines, provider_name, latency_ms, token_usage)

#### 3-2. Ollama Provider (`app/scanners/llm/ollama_provider.py`)
- [x] Connect to Ollama OpenAI-compatible API (`/v1/chat/completions`) via httpx
- [x] Force structured output via `format: json_schema` parameter
- [x] Implement `is_available()` via Ollama startup check (`GET /api/tags`)
- [x] Model existence verification (check if specified model has been pulled)
- [x] Timeout handling (60-second default for local inference)

#### 3-3. Anthropic Provider (`app/scanners/llm/anthropic_provider.py`)
- [x] Claude API integration via anthropic SDK
- [x] Structured output via `tool_use`
- [x] Implement `is_available()` via API key check
- [x] Timeout handling (30-second default)
- [x] Retry logic (429/5xx handling)

#### 3-4. OpenAI Provider (`app/scanners/llm/openai_provider.py`)
- [x] GPT API integration via openai SDK
- [x] Structured output via `response_format: json_schema`
- [x] Implement `is_available()` via API key check
- [x] Timeout/retry handling

#### 3-5. Deobfuscator (`app/scanners/llm/deobfuscator.py`)
- [x] Detection and decoding of Base64-encoded strings
- [x] Hex/unicode escape expansion
- [x] `eval()`/`exec()` argument extraction
- [x] Obfuscation score calculation (0.0-1.0)
  - Ratio of Base64/hex, variable name entropy, code readability
  - Skip local LLM and send directly to cloud when score is high (>= 0.7)

#### 3-6. Prompt Builder (`app/scanners/llm/prompt_builder.py`)
- [x] Common prompt construction logic shared across providers
- [x] Load and expand templates from `data/llm_prompts/`
- [x] Embed deobfuscation results
- [x] Apply context length limits (per provider)

#### 3-7. LLM Judge Router (`app/scanners/llm/judge.py`)
- [x] Implementation of 4 execution strategies:
  - `local_first`: Local -> escalate to cloud if confidence is low
  - `cloud_only`: Cloud LLMs only
  - `local_only`: Local LLM only
  - `consensus`: Execute both local + cloud, consensus verdict
- [x] Apply escalation threshold (`LOCAL_CONFIDENCE_THRESHOLD`)
- [x] Fallback chain: Ollama -> Anthropic -> OpenAI -> degraded mode
- [x] Cloud direct send based on obfuscation score
- [x] `ScannerProtocol` implementation (integration with existing pipeline)

#### 3-8. Cost Control and Monitoring
- [x] Daily cloud API call limit (`CLOUD_DAILY_LIMIT`)
- [x] Per-provider token usage logging
- [x] `app/db/models/llm_usage.py` -- Usage tracking model
- [x] Scan target file size limit (512KB default)

#### 3-9. Decision Engine Update (`app/decision/`)
- [x] Add LLM Judge scanner weight setting
- [x] Update 3-scanner result integration logic
- [x] Record LLM Judge `provider_name` in verdict metadata

#### 3-10. CLI Extension (`cli/commands/llm.py`)
- [x] `guard-proxy llm status` -- Check connectivity/model status for each provider
- [x] `guard-proxy llm test` -- Verify operation with test prompt
- [x] `guard-proxy llm usage` -- Display daily/monthly API usage

#### 3-11. Tests
- [x] `tests/test_scanners/test_llm/test_ollama_provider.py` (mock server)
- [x] `tests/test_scanners/test_llm/test_anthropic_provider.py` (mock API)
- [x] `tests/test_scanners/test_llm/test_openai_provider.py` (mock API)
- [x] `tests/test_scanners/test_llm/test_judge.py` (per-strategy tests)
- [x] `tests/test_scanners/test_llm/test_deobfuscator.py`
- [x] Fallback chain behavior tests
- [x] Escalation threshold behavior tests
- [x] Consensus strategy agreement logic tests

### Completion Criteria
- [x] `LLM_STRATEGY=local_only` completes judgment using only Ollama (Qwen3.5-9B)
- [x] `LLM_STRATEGY=local_first` escalates to cloud when confidence is low
- [x] `LLM_STRATEGY=cloud_only` completes judgment using only Claude/GPT
- [x] `LLM_STRATEGY=consensus` performs local + cloud consensus judgment
- [x] Fallback to cloud works correctly when Ollama is not running
- [x] Degraded mode works when all providers are down
- [x] Legitimate build scripts (node-gyp) do not trigger false positives
- [x] Malicious postinstall scripts equivalent to axios@1.14.1 are correctly detected
- [x] `guard-proxy llm status` shows status of all providers
- [x] Obfuscated code is passed to LLM after deobfuscation

---

## Phase 4: PyPI + RubyGems Support

### Goal
Provide equivalent protection for `pip install` / `gem install` / `bundle install`.

### PyPI Tasks (Complete)

- [x] `app/registry/pypi_client.py` -- PyPI JSON API + Simple API
- [x] `app/proxy/pypi.py` -- PEP 503 Simple API-compatible proxy + whl/sdist interception
- [x] `app/scanners/patterns/pypi_patterns.py` -- setup.py, .pth, cmdclass, cloud metadata detection
- [x] `app/scanners/static_analysis_pypi.py` -- PyPI-specific static analysis scanner
- [x] `data/llm_prompts/pypi_analysis.txt` -- LLM Judge prompt

### RubyGems Tasks (Complete)

- [x] `app/registry/rubygems_client.py` -- RubyGems JSON API + Compact Index
- [x] `app/proxy/rubygems.py` -- Compact Index passthrough + .gem interception
- [x] `app/scanners/patterns/rubygems_patterns.py` -- extconf.rb, ENV, eval, system, backtick detection
- [x] `app/scanners/static_analysis_rubygems.py` -- RubyGems-specific static analysis (mkmf false positive exclusion)
- [x] `data/llm_prompts/rubygems_analysis.txt` -- LLM Judge prompt
- [x] `app/utils/tarball.py` -- .gem extraction (outer tar -> metadata.gz + data.tar.gz)
- [x] `app/utils/install_hooks.py` -- gemspec extensions + rubygems_plugin.rb detection

### Completion Criteria
- [x] `pip install <package>` works correctly through the proxy
- [x] `gem install <gem> --source http://proxy:4875` works correctly through the proxy
- [x] `bundle config mirror` routes all traffic through the proxy
- [x] Suspicious code in .pth files and extconf.rb is detected

---

## Phase 5: Operations Hardening

### Goal
Achieve production-ready quality and operability.

### Tasks

#### 5-1. IOC Database
- [x] `app/db/models/ioc.py` -- IOC entry model
- [x] Initial data: known malicious package list
- [x] Periodic IOC list update mechanism (fetch from GitHub, etc.)

#### 5-2. Auditing and Observability
- [x] Enhanced audit logging (all requests, decision rationale recording)
- [x] Prometheus metrics (request count, block count, scan duration, per-LLM-provider usage)
- [x] Dashboard UI (optional)

#### 5-3. Notifications
- [x] Slack webhook integration (notify on block/quarantine)
- [x] GitHub Issue auto-creation (optional)

#### 5-4. DevContainer Support
- [x] devcontainer-feature creation
- [x] Automatic proxy configuration on container startup
- [x] Ollama sidecar container auto-start configuration

#### 5-5. CI/CD
- [x] GitHub Actions workflows (lint, test, build, publish)
- [x] PyPI publication preparation

#### 5-6. Documentation
- [x] README.md (English)
- [x] Usage guide
- [x] Contribution guide
- [x] LLM provider setup guide

### Completion Criteria
- [x] Quality suitable for open-source release
- [x] Installable via `pip install guard-proxy`
- [x] Integrable as a DevContainer
- [x] One-command startup via docker-compose including Ollama sidecar
