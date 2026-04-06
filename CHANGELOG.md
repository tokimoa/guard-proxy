# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-07

### Added

- **51 new tests** — test count 416 → 467
  - `NotificationService` (15 tests): webhook sending, rate limiting, error handling, verdict filtering
  - `BackgroundScanManager` (12 tests): scheduling, scanner execution, deny-cap safety guard, tmp dir cleanup, shutdown
  - LLM providers (24 tests): Anthropic, Ollama, OpenAI — judge, availability, JSON parsing, verdict normalization, error propagation

### Changed

- `.env.example` synced with `config.py` — added `SLACK_WEBHOOK_URL`, scanner toggle flags, advisory sync, deps.dev settings; removed stale `LLM_TRIGGER_ON_WARN`
- PyPI classifier updated from `Development Status :: 4 - Beta` to `5 - Production/Stable`

## [1.0.0] - 2026-04-07

First stable release. Declares API and proxy behavior stable for production use.

### Changed

- Version bump from 0.3.0 to 1.0.0 (no functional changes beyond 0.3.0)
- IOC database updated to 11,300+ known malicious packages (via weekly auto-sync)
- Removed stale 0.1.0 dist artifacts

## [0.3.0] - 2026-04-06

Operational polish, performance, and wiring up placeholder features.

### Added

- **Metrics integration** — `requests_total`, `scans_total`, `scan_{allow,quarantine,deny}`, `cache_hits`, `cache_misses` counters are now incremented in middleware, proxies, and cache service
- **Notification service wiring** — `NotificationService` initialized at startup when `SLACK_WEBHOOK_URL` is set; calls `notify_decision()` for deny/quarantine verdicts with rate limiting (10/min)
- **PyPI private mirror support** — download URLs derived from `PYPI_UPSTREAM_URL` config instead of hardcoded `files.pythonhosted.org`

### Changed

- **IOC regex pre-compilation** — C2 domain/IP boundary-matching regexes compiled once at load time instead of per-call
- **Tarball extraction hardening** — total extraction size limit (50 MB), file count limit (1000), `_MAX_FILE_SIZE` check on `package.json`, `tar.getmembers()` replaced with iterator to prevent tar bomb memory exhaustion
- **Pydantic schema hardening** — `DecisionResult.final_score` constrained to 0.0–1.0, `ScanRequest` fields have length limits, `NpmDistInfo.tarball` validates http/https, mutable defaults use `default_factory`
- **Cache upsert atomicity** — replaced delete-then-insert with SQLite `INSERT ON CONFLICT DO UPDATE`
- **Encapsulation cleanup** — added `upstream_url` property and `get()` method on registry clients; removed all `_private` field access from proxy code

## [0.2.0] - 2026-04-04

Security hardening and feature improvements from code review.

### Added

- **Alembic migration framework** with `env.py` and Mako template
- **Advisory sync pagination** — handles OSV API `next_page_token`
- **AST scanner alias tracking** — `import X as Y`, `from X import Y`
- **LLM consensus strategy** — runs local + cloud in parallel via `asyncio.gather`

### Changed

- **YARA scanner** — support regex and hex string types (not just literals); fix condition evaluator (`all of them`, multi-digit N, fallback)
- **Middleware** — pure ASGI instead of `BaseHTTPMiddleware` (no body buffering)
- **ReDoS prevention** — replaced unbounded `.*` with `.{0,500}` in all 54 pattern regexes
- **LLM clients** — reuse `httpx`/`anthropic`/`openai` clients across requests

### Security

- **SSRF prevention** — validate tarball/artifact URLs against upstream host; block absolute URLs in `forward_request`; strip auth headers on RubyGems forwarding
- **LLM verdict normalization** — strip, lowercase, validate to prevent injection
- **IOC matching** — word-boundary for domains, digit-boundary for IPs
- **Decision engine** — cap score at 1.0 to prevent unbounded scores
- Default bind to `127.0.0.1` instead of `0.0.0.0`
- Don't leak upstream URLs in error responses
- Redact `slack_webhook_url` and shorten API key exposure in `/config`

## [0.1.0] - 2026-04-03

### Added

- **Transparent proxy** for npm, PyPI, and RubyGems — intercepts `npm install` / `pip install` / `gem install`
- **10-layer fast-tier scanning** (< 1 second):
  - IOC database (11,000+ known malicious packages via DataDog dataset)
  - OSV/GHSA advisory check
  - Cooldown gate (blocks packages published less than N days ago)
  - Typosquatting detection (Levenshtein distance against 6,000+ popular packages)
  - Maintainer change tracking
  - Static analysis (160+ patterns across 3 registries)
  - YARA rules (GuardDog-compatible, pure Python via plyara)
  - Heuristics (entropy, binary detection, Unicode steganography)
  - AST analysis (Python `ast` + JavaScript `pyjsparser`)
- **LLM Judge** with 4 strategies:
  - `local_only` — Ollama only ($0/month)
  - `local_first` — Ollama with cloud escalation ($0.5–$2/month)
  - `cloud_only` — Claude/GPT ($5–$15/month)
  - `consensus` — local + cloud agreement
- **Smart two-tier scanning** — fast tier runs instantly, LLM runs in background for clean packages (no pip/npm timeout)
- **Decision engine** with weighted scoring (allow / quarantine / deny)
- **CycloneDX 1.6 SBOM** output for every scanned package
- **CLI** (`guard-proxy start`, `scan`, `config`, `status`, `sbom`, `sync-ioc`)
- **Admin API** (health, cache, config, metrics, SBOM endpoints)
- **SQLite** cache, audit log, and IOC database
- **Docker** support with Ollama sidecar
- **CI/CD** — GitHub Actions for lint, test, nightly, weekly IOC sync
- **Documentation** — English + Japanese bilingual docs

### Detection Benchmarks

| Benchmark | Detected | Rate |
|---|---|---|
| GuardDog rules (28 source + metadata) | 28/28 | 100% |
| BKC attack taxonomy (12 categories) | 12/12 | 100% |
| Real-world incidents 2024–2026 (23 CVEs) | 23/23 | 100% |
| False positives (100 popular packages) | 0 | 0% |

[1.1.0]: https://github.com/tokimoa/guard-proxy/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tokimoa/guard-proxy/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/tokimoa/guard-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tokimoa/guard-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tokimoa/guard-proxy/releases/tag/v0.1.0
