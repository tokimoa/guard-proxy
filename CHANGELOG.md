# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/tokimoa/guard-proxy/releases/tag/v0.1.0
