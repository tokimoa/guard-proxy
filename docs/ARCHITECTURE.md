# Guard Proxy - Architecture Document

> Japanese version: [ARCHITECTURE_ja.md](ARCHITECTURE_ja.md)

## Overview

Guard Proxy is a security proxy that protects developers from supply chain attacks targeting npm, PyPI, and RubyGems. It transparently intercepts `npm install` / `pip install` / `gem install` commands, verifies package safety, and only then permits the download.

## Background and Motivation

This project was designed in response to the following supply chain attacks that occurred in March 2026:

- **axios@1.14.1 / 0.30.4** -- RAT distribution via npm account takeover (2026/3/31)
- **litellm@1.82.7 / 1.82.8** -- Credential stealer via CI/CD pipeline compromise (2026/3/24)

These attacks were **executed immediately at install time** through `postinstall` scripts and `.pth` files, stealing credentials from development machines.

## System Architecture Diagram

```
Developer (npm install / pip install / gem install)
    |
    v
+----------------------------------------------------------+
|                     Guard Proxy                           |
|                                                          |
|  +----------+                                            |
|  |  Cache    |-- hit -> immediate allow/deny             |
|  | (SQLite)  |                                            |
|  +----+-----+                                            |
|       | miss                                              |
|       v                                                  |
|  +------------------+                                    |
|  | Registry Client   |-- fetch metadata from upstream    |
|  | (npm / PyPI API)  |   (publish date, author, deps)    |
|  +----+-------------+                                    |
|       v                                                  |
|  +--------------------------------------------------+    |
|  |              Scan Pipeline                        |    |
|  |                                                  |    |
|  |  +------------+  +--------------+                |    |
|  |  |  Cooldown   |->|   Static     |                |    |
|  |  |   Gate      |  |  Analysis    |                |    |
|  |  +------------+  +------+-------+                |    |
|  |                         | warn or above           |    |
|  |                         v                        |    |
|  |  +--------------------------------------------+  |    |
|  |  |         LLM Judge Router                    |  |    |
|  |  |                                            |  |    |
|  |  |  strategy: local_first | cloud_only        |  |    |
|  |  |           | local_only | consensus         |  |    |
|  |  |                                            |  |    |
|  |  |  +----------+ +---------+ +----------+    |  |    |
|  |  |  |  Local    | | Claude  | |   GPT    |    |  |    |
|  |  |  | (Ollama)  | |  API    | |   API    |    |  |    |
|  |  |  | Qwen3.5   | | Sonnet  | |   5.4    |    |  |    |
|  |  |  | etc.      | |         | |          |    |  |    |
|  |  |  | $0/unlim. | | low cost| | low cost |    |  |    |
|  |  |  +----------+ +---------+ +----------+    |  |    |
|  |  |           |         |          |           |  |    |
|  |  |           +---------+----------+           |  |    |
|  |  |                     |                      |  |    |
|  |  |        Result aggregation + escalation     |  |    |
|  |  +---------------------+----------------------+  |    |
|  +----------------------------+---------------------+    |
|                            v                              |
|  +--------------------------------------------------+    |
|  |              Decision Engine                      |    |
|  |  Weighted scoring -> allow/deny/quarantine        |    |
|  +----+---------------------------------------------+    |
|       |                                                  |
|       +- allow      -> relay upstream response           |
|       +- quarantine -> warning log + relay or block      |
|       +- deny       -> 403 error + reason explanation    |
|                                                          |
|  +----------+  +--------------+                          |
|  | Audit Log |  | Admin API    |                          |
|  | (SQLite)  |  | (FastAPI)    |                          |
|  +----------+  +--------------+                          |
+----------------------------------------------------------+
    |
    v
Upstream Registries (registry.npmjs.org / pypi.org / rubygems.org)
```

## Component Details

### 1. Proxy Layer (`app/proxy/`)

Handles HTTP request interception and relaying to upstream registries.

| File | Responsibility |
|---|---|
| `base.py` | Abstract proxy base class. Common request relay logic |
| `npm.py` | npm registry API protocol implementation, including tarball URL redirect handling |
| `pypi.py` | PyPI Simple API / JSON API protocol implementation |
| `rubygems.py` | RubyGems Compact Index / gem download protocol implementation |
| `middleware.py` | Common middleware for request logging, timeout control, etc. |

#### npm Proxy Communication Flow

```
1. GET /<package>           -> Fetch package metadata
2. GET /<package>/-/<tarball> -> Tarball download (scan happens here)
```

#### PyPI Proxy Communication Flow

```
1. GET /simple/<package>/     -> Fetch package index
2. GET /packages/<path>.whl   -> whl/sdist download (scan happens here)
```

#### RubyGems Proxy Communication Flow

```
1. GET /info/<gem>             -> Compact Index metadata fetch (passthrough)
2. GET /versions               -> Version list (passthrough)
3. GET /gems/<gem>-<ver>.gem   -> Gem download (scan happens here)
```

### 2. Scanner Layer (`app/scanners/`)

Three types of scanners implement the common `ScannerProtocol`.

```python
class ScannerProtocol(Protocol):
    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult: ...

class ScanResult(BaseModel):
    scanner_name: str
    verdict: Literal["pass", "warn", "fail"]
    confidence: float  # 0.0 - 1.0
    details: str
    metadata: dict[str, Any] = {}
```

#### 2a. Cooldown Gate (`cooldown.py`)

Verifies the package publish date and warns/blocks packages published less than N days ago.

- **Input**: Package metadata (publish date)
- **Decision**: `days since publish < COOLDOWN_DAYS` -> fail / warn
- **Configuration**: `COOLDOWN_DAYS` (default: 7), `COOLDOWN_ACTION` (warn / deny)

#### 2b. Static Analysis (`static_analysis.py`)

Performs pattern matching against package install scripts and related files.

**npm scan targets:**
- `package.json` -> `scripts.postinstall`, `scripts.preinstall`, `scripts.install`
- Script file contents

**PyPI scan targets:**
- `setup.py` -> `cmdclass`, install hooks
- `*.pth` files
- `__init__.py` (code executed at import time)

**RubyGems scan targets:**
- `extconf.rb` -> Native extension build script (executed at install time)
- `ext/**/*.rb` -> Native extension sources
- `rubygems_plugin.rb` -> Automatically executed when gem is loaded
- `Rakefile` -> Build task definitions

**Detection patterns:**
- Bulk environment variable access (`os.environ`, `process.env`)
- Credential file access (`~/.ssh`, `~/.aws`)
- Base64 decode -> eval/exec
- HTTP communication to external domains
- Process persistence (systemd, launchd, crontab)
- Obfuscated code

**Deobfuscation preprocessing:**
Static analysis handles preprocessing to improve LLM Judge accuracy, in addition to simple pattern matching.

- Detection and decoding of Base64-encoded strings
- `eval`/`exec` argument expansion
- Obfuscation score calculation (high score cases skip local LLM and escalate directly to cloud)

#### 2c. LLM-as-a-Judge (`app/scanners/llm/`)

Multi-provider LLM judgment engine. Examines cases that are difficult to determine through static analysis alone.

##### Architecture

```
+----------------------------------------------------------+
|                    LLM Judge Router                       |
|                    (llm/judge.py)                         |
|                                                          |
|  Selects and executes providers based on strategy         |
|                                                          |
|  +------------------------------------------------------+|
|  |              LLMProvider (Protocol)                   ||
|  |              (llm/provider.py)                        ||
|  |                                                      ||
|  |  judge(prompt, schema) -> JudgeResult                ||
|  |  is_available() -> bool                              ||
|  |  provider_name -> str                                ||
|  +------------------------------------------------------+|
|       ^              ^              ^                    |
|       |              |              |                    |
|  +----+-----+  +-----+-----+  +----+-----+             |
|  |  Ollama   |  | Anthropic |  |  OpenAI  |             |
|  | Provider  |  | Provider  |  | Provider |             |
|  |           |  |           |  |          |             |
|  | OpenAI-   |  | anthropic |  | openai   |             |
|  | compat API|  | SDK       |  | SDK      |             |
|  |           |  |           |  |          |             |
|  | Structured|  | tool_use  |  | response |             |
|  | output:   |  | for JSON  |  | _format  |             |
|  | format=   |  | output    |  | for JSON |             |
|  | json_schema| |           |  |          |             |
|  +-----------+  +-----------+  +----------+             |
|                                                          |
|  +------------------------------------------------------+|
|  |           Prompt Builder (llm/prompt_builder.py)     ||
|  |           Common prompt construction across providers ||
|  +------------------------------------------------------+|
|                                                          |
|  +------------------------------------------------------+|
|  |           Deobfuscator (llm/deobfuscator.py)         ||
|  |           Preprocessing such as Base64 expansion      ||
|  +------------------------------------------------------+|
+----------------------------------------------------------+
```

##### Execution Strategies

| Strategy | Behavior | Use Case |
|---|---|---|
| `local_first` | Judge with local LLM -> escalate to cloud if confidence is low | **Recommended default**. Minimizes cost |
| `cloud_only` | Use only cloud LLMs (Claude/GPT) | Environments without local LLM setup |
| `local_only` | Use only local LLM (Ollama) | Offline environments, fully free operation |
| `consensus` | Execute both local and cloud, determine by consensus | High-security environments |

##### `local_first` Strategy Flow

```
Receive suspicious script from Static Analysis
    |
    v
Preprocess with Deobfuscator (Base64 expansion, etc.)
    |
    v
Check obfuscation score
    |
    +- high -> Send directly to cloud LLM (small models may lack accuracy)
    |
    +- low to medium -> Judge with local LLM (Ollama)
                    |
                    +- confidence >= 0.8 -> Accept result ($0)
                    |
                    +- confidence < 0.8 -> Escalate to cloud LLM
                                              |
                                              +- Anthropic (primary)
                                              |
                                              +- OpenAI (fallback)
```

##### Fallback Chain

```
1. Local LLM (Ollama) is running -> use it
2. Ollama not running or timeout -> cloud primary (Anthropic)
3. Anthropic API failure -> cloud fallback (OpenAI)
4. All LLMs unavailable -> decide using Static Analysis results only (degraded mode)
```

##### Cost Estimate

```
Assumption: 50 new packages fetched via npm install per day

Static Analysis -> LLM invocation targets: 2-3 packages (5%)

local_only:   $0/month
local_first:  $0.5-$2/month (escalation portion only)
cloud_only:   $5-$15/month
consensus:    $5-$15/month (both local + cloud)
```

##### Supported Providers and Models

| Provider | Example Models | Structured Output Method | Characteristics |
|---|---|---|---|
| Ollama (local) | **Qwen3.5-9B** (default), Gemma4-26B, Qwen3-Coder-30B, Mistral Small 3.2 | `format: json_schema` (GBNF grammar-based) | $0, any Ollama-supported model |
| Anthropic (cloud) | Claude Sonnet 4.6 | Structured output via `tool_use` | High accuracy, low latency |
| OpenAI (cloud) | GPT-5.4 | `response_format: json_schema` | High accuracy, used as fallback |
| OpenAI-compatible (generic) | Any | OpenAI-compatible API | Support for custom servers like vLLM |

> See [LLM Setup Guide](LLM_SETUP_GUIDE.md) for detailed model recommendations and RAM requirements.

### 3. Decision Engine (`app/decision/`)

Integrates results from all scanners using weighted scoring and renders a final verdict.

```
Final Score = SUM(scanner_weight x verdict_score x confidence)

verdict_score:
  pass = 0.0
  warn = 0.5
  fail = 1.0

Verdict:
  allow:      score < WARN_THRESHOLD (0.3)
  quarantine: WARN_THRESHOLD <= score < DENY_THRESHOLD (0.7)
  deny:       score >= DENY_THRESHOLD (0.7)
```

### 4. Registry Client (`app/registry/`)

Handles communication with upstream registry APIs (npmjs.org / pypi.org / rubygems.org).

- Fetches package metadata (publish date, author, dependency list)
- Downloads tarball / whl / .gem files
- httpx-based async HTTP client
- Registry-specific API protocol support (npm JSON API / PyPI Simple API / RubyGems Compact Index)

### 5. Database (`app/db/`)

Uses SQLite for persistent storage of the following data.

| Table | Purpose |
|---|---|
| `scan_results` | Scan result cache (pkg name + version + hash -> verdict) |
| `ioc_entries` | Known IOCs (malicious package names, C2 domains/IPs) |
| `audit_logs` | Audit log for all requests (verdict, timestamp) |
| `llm_usage` | LLM usage tracking (per provider, daily aggregation) |

### 6. CLI (`cli/`)

Typer-based command-line interface.

```bash
guard-proxy start              # Start the proxy
guard-proxy scan <pkg>         # Manual scan
guard-proxy config show        # Show configuration
guard-proxy cache list         # List cache entries
guard-proxy status             # Check status
guard-proxy llm status         # Check LLM provider connectivity
guard-proxy llm test           # Test LLM provider operation
```

### 7. Admin API (`app/api/`)

REST API for proxy administration (FastAPI).

- `GET /health` -- Health check
- `POST /scan` -- Manual scan execution
- `GET /cache` -- Cache management
- `GET /config` -- Current configuration
- `GET /llm/status` -- LLM provider status (availability per provider, daily usage)

## Directory Structure

```
guard-proxy/
+-- app/                              # Main application
|   +-- main.py                       # FastAPI application entry point
|   +-- core/                         # Configuration, logging, exception definitions
|   +-- proxy/                        # npm/PyPI/RubyGems proxy engine
|   +-- scanners/                     # Security scanners
|   |   +-- patterns/                 # Malicious pattern definitions
|   |   +-- llm/                      # LLM Judge subpackage
|   |       +-- judge.py              # LLM Judge main logic (router)
|   |       +-- provider.py           # LLMProvider abstract base class
|   |       +-- ollama_provider.py    # Ollama (local LLM) provider
|   |       +-- anthropic_provider.py # Claude API provider
|   |       +-- openai_provider.py    # GPT API provider
|   |       +-- prompt_builder.py     # Prompt construction (shared across providers)
|   |       +-- deobfuscator.py       # Preprocessing (Base64 expansion, obfuscation scoring)
|   +-- decision/                     # Decision engine
|   +-- registry/                     # Registry API clients
|   +-- db/                           # SQLite database
|   +-- api/                          # Admin REST API
|   +-- schemas/                      # Pydantic schemas
|   +-- utils/                        # Utilities
+-- cli/                              # CLI tool (Typer)
+-- deployment/                       # Docker/docker-compose
+-- data/                             # Static data (IOC lists, LLM prompts)
|   +-- llm_prompts/                  # LLM prompt templates
+-- docs/                             # Design documents
+-- tests/                            # Tests
|   +-- test_scanners/
|       +-- test_llm/                 # LLM Judge tests
+-- debug/                            # Debug files (gitignored)
```

## Technology Stack

| Purpose | Technology |
|---|---|
| Web framework | FastAPI |
| HTTP client | httpx |
| CLI | Typer + Rich |
| Database | SQLite + SQLAlchemy |
| LLM (local) | Ollama (OpenAI-compatible API) |
| LLM (cloud) | Claude API (anthropic SDK), GPT API (openai SDK) |
| Validation | Pydantic v2 |
| Logging | loguru |
| Package management | uv |
| Linter/Formatter | ruff |
| Testing | pytest + pytest-asyncio |

## Network Configuration

```
Local Development:
  Guard Proxy:
    npm proxy:       localhost:4873
    PyPI proxy:      localhost:4874
    RubyGems proxy:  localhost:4875
    Admin API:       localhost:8100
  Ollama:            localhost:11434 (LLM inference)

Team Server:
  Guard Proxy:
    npm proxy:       guard.internal.example.com:4873
    PyPI proxy:      guard.internal.example.com:4874
    RubyGems proxy:  guard.internal.example.com:4875
    Admin API:       guard.internal.example.com:8100
  Ollama:        Same server or separate host (GPU-equipped machine)
```
