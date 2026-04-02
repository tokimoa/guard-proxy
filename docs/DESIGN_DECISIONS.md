# Guard Proxy - Design Decisions

> Japanese version: [DESIGN_DECISIONS_ja.md](DESIGN_DECISIONS_ja.md)

Each design decision is documented with its "Background", "Options", "Decision", "Rationale", "Tradeoffs", and "Changeability".

---

## DD-01: Proxy Approach -- Custom FastAPI Transparent Proxy

### Background
A decision was needed on whether to use existing OSS tools (Verdaccio, devpi, etc.) or build a custom implementation as the proxy for npm/PyPI/RubyGems.

### Options
1. **Fork/extend Verdaccio (npm) + devpi (Python) via plugins**
2. **Custom FastAPI-based transparent proxy**
3. **HTTP-level interception via MITM Proxy (mitmproxy, etc.)**

### Decision
**Option 2: Custom FastAPI-based transparent proxy**

### Rationale
- Verdaccio is a Node.js ecosystem tool; incorporating it into a Python project would split the technology stack
- devpi is PyPI-specific and cannot handle npm/PyPI/RubyGems under a unified architecture
- Relaying requests to upstream registries via FastAPI's `httpx` integrates naturally with the scan pipeline
- mitmproxy is too general-purpose and cannot make decisions based on registry API semantics

### Tradeoffs
- Protocol compatibility for the npm registry API, PyPI Simple API, and RubyGems Compact Index API must be maintained in-house
- Particular care is needed for npm tarball URL redirect handling and scoped packages (`@scope/pkg`)
- Cannot leverage mature caching mechanisms and UIs from existing tools

### Changeability
Low. This is fundamental to the architecture, so mid-project changes would be costly. However, npm/PyPI/RubyGems APIs are stable, making compatibility maintenance realistic.

---

## DD-02: Scanner Architecture -- Pipeline + Protocol

### Background
A decision was needed on how to structure and combine multiple scanning methods (cooldown, static analysis, LLM).

### Options
1. **Monolithic: Execute all checks in a single function**
2. **Pipeline + Protocol: Modularize each scanner independently, execute sequentially**
3. **Plugin: Dynamic loading as external plugins**

### Decision
**Option 2: Pipeline + Protocol**

### Rationale
- Responsibilities of each scanner are clearly separated
- Adding new scanners does not require changes to existing code (Open/Closed Principle)
- Pipeline order can be controlled via configuration, and disabling specific scanners is straightforward
- Type safety through Python Protocol classes

### Tradeoffs
- Less flexible than a Plugin approach (external developers need code changes to add custom scanners)
- Pipeline order can affect results (whether to skip later scanners when an earlier one returns fail)

### Changeability
Medium. Extending from Protocol to Plugin is relatively straightforward.

---

## DD-03: Decision Engine -- Weighted Scoring

### Background
A decision was needed on how to integrate results from multiple scanners into a final verdict (allow/deny/quarantine).

### Options
1. **Rule-based: Immediately deny if any scanner returns fail**
2. **Weighted scoring: Calculate using each scanner's result x weight x confidence**
3. **Delegate final judgment to the LLM**

### Decision
**Option 2: Weighted scoring**

### Rationale
- Rule-based (Option 1) is too strict when false positives occur
- LLM final judgment (Option 3) incurs too much cost and latency
- Weighting allows flexible verdicts that reflect each scanner's confidence level
- Thresholds can be adjusted in configuration to tune for the user's environment

### Scoring Formula

```
Final Score = SUM(scanner_weight x verdict_score x confidence)

verdict_score:
  pass = 0.0
  warn = 0.5
  fail = 1.0

Default weights:
  cooldown:        0.3
  static_analysis: 0.4
  llm_judge:       0.3

Verdict:
  allow:      score < 0.3
  quarantine: 0.3 <= score < 0.7
  deny:       score >= 0.7
```

### Tradeoffs
- Weights and thresholds require tuning (setting initial values is challenging)
- Individual scanner "absolute deny" cases (e.g., known malware) need to bypass scoring

### Changeability
Medium. Threshold adjustments are easy, but changing the scoring model itself requires redesigning the decision engine.

---

## DD-04: Database -- SQLite

### Background
A decision was needed on the persistent storage for scan result cache, IOC database, and audit logs.

### Options
1. **Redis**
2. **SQLite**
3. **PostgreSQL**
4. **File-based (JSON/YAML)**

### Decision
**Option 2: SQLite**

### Rationale
- Guard Proxy's primary use case is local developers (single user)
- No external dependencies (bundled with Python's standard library)
- WAL mode enables concurrent read/write operations
- Even for team-shared use, SQLite handles caches of tens of thousands of packages easily
- Backup is simply a file copy

### Tradeoffs
- Not suitable for high-frequency concurrent writes (when used at scale on a team server)
- Limited full-text search and JSON type support

### Changeability
High. Since access goes through SQLAlchemy, migration to PostgreSQL or similar is relatively straightforward.

---

## DD-05: LLM Architecture -- Multi-Provider + Execution Strategy Pattern

### Background
The cost/latency and accuracy balance of LLM scanning needs to be flexibly adjustable based on the user's environment. Given the practical maturity of local LLMs (Ollama) in 2026, operation without cloud API dependency should also be possible.

### Options
1. **Single provider: Claude API only**
2. **Multiple cloud providers only (Claude + GPT)**
3. **Local + cloud multi-provider + execution strategies**

### Decision
**Option 3: Multi-provider + execution strategy pattern**

### Rationale

#### Removing OSS Adoption Barriers
- "Requires an API key" is one of the biggest adoption barriers for OSS tools
- The `local_only` strategy enables full functionality with no API key and at zero cost
- Qwen3.5-9B runs at 30-50 tok/s on M4 Pro; script scanning (a few hundred lines) completes in 1-3 seconds
- 6.6GB memory consumption via Ollama, fully practical on development machines
- Alternative models (Gemma4-26B, Qwen3-Coder-30B, Mistral Small 3.2) provide higher accuracy for users with 32GB+ RAM

#### Cost Optimization
- The `local_first` strategy processes the vast majority of scans at $0
- Cloud API calls can be suppressed to 0.2-1.5% of total scans
- Monthly costs of $0.5-$2 are realistic

#### Graduated Accuracy Guarantee
- Local LLM (9B) is sufficiently accurate for clear cases (safe / obviously malicious)
- Only gray zone cases (confidence < 0.8) are escalated to cloud, balancing accuracy and cost
- Obfuscated code is preprocessed by the static analysis deobfuscator before being passed to the LLM, compensating for small model weaknesses

#### Unified Interface
- Ollama's OpenAI-compatible API makes provider unification natural
- The `LLMProvider` Protocol abstraction makes adding new providers straightforward
- Custom servers like vLLM can be supported via the `OpenAIProvider`

### Four Execution Strategies

| Strategy | Behavior | Use Case | Cost |
|---|---|---|---|
| `local_first` | Local -> escalate to cloud if confidence is low | **Recommended default** | $0.5-$2/month |
| `cloud_only` | Use only cloud LLMs | Environments without Ollama | $5-$15/month |
| `local_only` | Use only local LLM | Offline / completely free | $0/month |
| `consensus` | Execute both local + cloud -> consensus verdict | High-security environments | $5-$15/month |

### Fallback Chain

```
1. Local LLM (Ollama) is running -> use it
2. Ollama not running or timeout -> cloud primary (Anthropic)
3. Anthropic API failure -> cloud fallback (OpenAI)
4. All LLMs unavailable -> decide using Static Analysis results only (degraded mode)
```

At any stage, if all LLMs are unavailable, the system continues making decisions based on static analysis results alone. Since Guard Proxy is a security tool, it does not allow LLM failures to halt the entire system.

### Deobfuscator Integration

```
                  Obfuscation Score
                      |
    +-----------------+-----------------+
    | low to medium   |                 | high (>= 0.7)
    | (< 0.7)         |                 |
    v                 |                 v
Judge with local LLM  |        Send directly to cloud LLM
                      |        (small models may lack accuracy)
```

Code with a high obfuscation score is sent directly to the cloud, skipping local processing, because 9B models have reduced analysis accuracy for obfuscated code. This decision is based on benchmark findings (small LLMs are weak at obfuscated code analysis).

### Structured Output Guarantee

Each provider uses a different structured output mechanism, but the output schema is unified.

| Provider | Structured Output Method | Reliability |
|---|---|---|
| Ollama | `format: json_schema` (GBNF grammar-based) | Stable with 7B+ models |
| Anthropic | Structured output via `tool_use` | High |
| OpenAI | `response_format: json_schema` | High |

Models smaller than 7B (including Q3 or lower quantization) may produce unstable JSON output. Therefore, the default `OLLAMA_MODEL` is `qwen3.5:9b`, and the recommended minimum size is documented.

### Tradeoffs
- Verdict results may vary between providers
  - Mitigated by using the consensus strategy for agreement
  - `provider_name` is recorded in results for later analysis
- Local LLM accuracy may be inferior to cloud LLM in some cases
  - Compensated by the escalation mechanism and deobfuscator
  - Users of `local_only` accept this risk by default
- Increased implementation complexity
  - Unified via the `LLMProvider` Protocol; each provider is an independent module
  - Adding a new provider requires only adding a single file

### Changeability
High. Adding a new provider requires only a single file implementing `LLMProvider`. Adding strategies requires only extending `judge.py`.

---

## DD-06: Default Behavior -- Warn Mode (Not Enforce)

### Background
A decision was needed on the default behavior when blocking.

### Options
1. **Enforce (block install on deny)**
2. **Warn (log warning only on deny, allow install)**

### Decision
**Option 2: Warn mode as default**

### Rationale
- If false positives block installs during initial deployment, the developer experience degrades and adoption is rejected
- It is realistic to first operate in Warn mode, verify the false positive rate, and then switch to Enforce
- The experience of "I installed it and my development stopped" is irrecoverable

### Configuration
```
DECISION_MODE=warn     # Warnings only (default)
DECISION_MODE=enforce  # Blocking enabled
```

### Changeability
High. Switchable with a single environment variable.

---

## DD-07: Package Extraction Policy -- Extract Only Install Script Files

### Background
A decision was needed on whether to fully extract package tarballs/whls or extract only the necessary files.

### Options
1. **Full extraction and scan**
2. **Extract only install script-related files**

### Decision
**Option 2: Extract only install script-related files**

### Rationale
- Full extraction of large packages can reach hundreds of MB to several GB
- Attack entry points are limited to files that are automatically executed at install time
- Narrowing scan targets dramatically improves speed

### Extraction Targets

#### npm
- `package.json` (scripts.postinstall, scripts.preinstall, scripts.install)
- Files referenced by the above scripts

#### PyPI
- `setup.py`
- `setup.cfg`
- `pyproject.toml`
- `*.pth`
- `__init__.py` for each package

#### RubyGems
- `metadata.gz` -> gemspec metadata (checking the `extensions` array)
- `extconf.rb` (any path) -- native extension build script
- `ext/**/*.rb` -- native extension sources
- `rubygems_plugin.rb` -- automatically executed when gem is loaded
- `Rakefile`

### Tradeoffs
- Malicious code executed at times other than install (e.g., import time) may not be detected
  - Partially addressed by PyPI `__init__.py` scanning
- When scripts reference external files, reference resolution is needed

### Changeability
Medium. Adding a full extraction mode is possible, but involves a performance tradeoff.

---

## DD-08: Default LLM Strategy -- `local_first`

### Background
A decision was needed on the default execution strategy for the multi-provider LLM Judge.

### Options
1. **`cloud_only` as default** (similar to traditional SaaS tools)
2. **`local_first` as default** (local priority, cloud only when needed)
3. **`local_only` as default** (fully local)

### Decision
**Option 2: `local_first` as default**

### Rationale
- As an OSS tool, prioritizing the "install and use immediately" experience
- If Ollama is installed, it works at $0; if not, it falls back to cloud
- `local_only` carries high accuracy risk (no escalation possible)
- `cloud_only` has a high adoption barrier due to required API keys
- `local_first` is the most flexible choice: "Ollama recommended but works without it"

### Auto-Detection
At startup, Ollama availability is automatically detected, and the system behaves as follows:

```
Ollama running + model available -> operate as local_first
Ollama not running or model missing -> auto-fallback to cloud_only
Cloud API key also not configured -> static analysis only (LLM disabled, warning displayed)
```

### Changeability
High. Instantly switchable via the `LLM_STRATEGY` environment variable.
