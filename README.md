# Guard Proxy

[日本語ドキュメント](docs/ARCHITECTURE_ja.md) | [English docs](docs/)

> Supply chain security proxy for npm, PyPI, RubyGems, and Go modules.
> Intercepts `npm install` / `pip install` / `gem install` / `go get` transparently and blocks malicious packages before they execute.

[![CI](https://github.com/tokimoa/guard-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/tokimoa/guard-proxy/actions/workflows/ci.yml)

## Why Guard Proxy?

Supply chain attacks hit **at install time** — `postinstall` scripts, `setup.py` hooks, and `extconf.rb` run code the moment you install a package. By the time `npm audit` or `pip-audit` reports a problem, your credentials are already stolen.

Guard Proxy sits between your package manager and the registry, scanning every package **before** it reaches your machine.

**What makes it different:**

| | Guard Proxy | npm audit / pip-audit | Socket.dev | Snyk |
|---|---|---|---|---|
| Blocks at install time | **Yes** | No (post-install) | Enterprise only | No |
| Detects malicious code | **Yes** | No (CVEs only) | Yes | Reactive only |
| Local LLM support | **Yes (Ollama)** | No | No | No |
| Open source | **Yes (MIT)** | Built-in | No | No |
| Transparent proxy | **Yes** | N/A | Enterprise only | No |

## Quick Start

### Minimal Setup (No LLM, 30 seconds)

```bash
# Install
git clone https://github.com/tokimoa/guard-proxy.git
cd guard-proxy
uv sync

# Start proxy
guard-proxy start

# Use npm through the proxy
echo "registry=http://localhost:4873" >> .npmrc
npm install express    # Scanned and allowed ✅
```

### With Local LLM (Recommended)

```bash
# Install Ollama (https://ollama.com)
ollama pull qwen3.5:latest

# Configure Guard Proxy
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:latest
DECISION_MODE=warn
EOF

# Start proxy
guard-proxy start
```

### With Cloud LLM (Claude API)

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-xxxxx
DECISION_MODE=warn
EOF

guard-proxy start
```

## Configuring Package Managers

### npm
```bash
# Project-level
echo "registry=http://localhost:4873" >> .npmrc

# Or per-command
npm install --registry=http://localhost:4873 express
```

### pip
```bash
pip install --index-url http://localhost:4873/simple/ --trusted-host localhost flask

# Or set in pip.conf
# [global]
# index-url = http://localhost:4873/simple/
# trusted-host = localhost
```

### gem / bundler
```bash
# gem
gem install sinatra --source http://localhost:4875

# bundler (recommended — all traffic routed through proxy)
bundle config set --global mirror.https://rubygems.org http://localhost:4875
```

### go
```bash
GOPROXY=http://localhost:4876,direct go get github.com/gin-gonic/gin

# Or set permanently
export GOPROXY=http://localhost:4876,direct
export GONOSUMCHECK=*
```

## How It Works

```
npm install express
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                      Guard Proxy                             │
│                                                             │
│  Fast Tier (< 1 second, always runs)                        │
│  ├─ IOC Database (11,000+ known malicious packages)         │
│  ├─ OSV/GHSA Advisory Check                                │
│  ├─ Cooldown Gate (new package age)                         │
│  ├─ Typosquatting Detection (Levenshtein, 6000+ packages)   │
│  ├─ Maintainer Change Tracking                              │
│  ├─ Static Analysis (180+ patterns × 4 registries)          │
│  ├─ YARA Rules (GuardDog compatible)                        │
│  ├─ Heuristics (entropy, binary, Unicode steganography)     │
│  └─ AST Analysis (variable indirection, dataflow)           │
│                                                             │
│  Slow Tier (background, for suspicious packages)            │
│  ├─ Dependency Graph Analysis (via deps.dev)                │
│  └─ LLM Judge (Ollama / Claude / GPT)                      │
│                                                             │
│  Decision: allow ✅ │ quarantine ⚠️ │ deny ❌               │
│                                                             │
│  SBOM: CycloneDX 1.6 output for each package               │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
express@4.21.2 + 69 dependencies → all scanned, all allowed ✅
```

## CLI Commands

```bash
guard-proxy start                             # Start proxy server
guard-proxy scan express                      # Scan npm package
guard-proxy scan flask@3.1.1 --registry pypi  # Scan PyPI package
guard-proxy scan sinatra --registry rubygems  # Scan RubyGem
guard-proxy config                            # Show configuration
guard-proxy status                            # Show proxy status
guard-proxy sync-ioc                          # Sync IOC from DataDog dataset
guard-proxy sbom                              # Export SBOM (CycloneDX JSON)
guard-proxy sbom --file sbom.json             # Export to file
```

## Configuration Modes

> **Detailed LLM setup guide**: [docs/LLM_SETUP_GUIDE.md](docs/LLM_SETUP_GUIDE.md)
> — OS-specific Ollama installation, model selection guide, cost estimation, troubleshooting

### Mode 1: Static Analysis Only (Default, No LLM)

Zero external dependencies. Fast, lightweight.

```env
LLM_ENABLED=false
DECISION_MODE=warn
```

**Detects**: known malicious packages, typosquatting, obfuscated code, credential theft, reverse shells, cryptominers, etc.

### Mode 2: Local LLM (Ollama, Free, Recommended)

Adds AI-powered judgment for suspicious packages. Runs entirely on your machine.

```env
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:latest
```

**Requirements**: [Ollama](https://ollama.com) + 8GB RAM (for Qwen 3.5 8B model). Also supports Gemma 4, Qwen3-Coder, Mistral Small 3.2 — see [LLM Setup Guide](docs/LLM_SETUP_GUIDE.md)

**How it works**: Fast-tier scanners run first (< 1 second). If a package looks suspicious, the LLM analyzes the code. If the package looks safe, the LLM runs in the background to warm the cache — your install isn't delayed.

### Mode 3: Cloud LLM (Claude / GPT)

Higher accuracy for edge cases. Requires API key.

```env
LLM_ENABLED=true
LLM_STRATEGY=local_first          # Try Ollama first, escalate to cloud if unsure
ANTHROPIC_API_KEY=sk-ant-xxxxx    # Claude API
OPENAI_API_KEY=sk-xxxxx           # GPT API (fallback)
```

### Mode 4: Enforce (Block Mode)

Actually prevents installation of suspicious packages (default is warn-only).

```env
DECISION_MODE=enforce    # Block suspicious packages (default: warn)
COOLDOWN_DAYS=14         # Longer cooldown for new packages
```

## Security Benchmarks

Evaluated against public, third-party benchmarks — not just internal tests.

### IOC Database Coverage (Full Dataset Validation)

Real data fetched from public APIs and validated against our IOC database:

| Dataset | Source | Packages | Matched | Coverage |
|---|---|---|---|---|
| **DataDog npm** | [manifest.json](https://github.com/DataDog/malicious-software-packages-dataset) | 9,505 | 9,505 | **100.0%** |
| **DataDog PyPI** | [manifest.json](https://github.com/DataDog/malicious-software-packages-dataset) | 1,786 | 1,786 | **100.0%** |
| **OSSF cross-ref** (npm sample) | [osv.dev API](https://github.com/ossf/malicious-packages) | 200 | 192 | **96.0%** |
| **OSSF cross-ref** (PyPI sample) | [osv.dev API](https://github.com/ossf/malicious-packages) | 200 | 141 | **70.5%** |
| **OSPTrack** (PyPI, from log) | [Zenodo](https://zenodo.org/records/14197378) | 8,134 | 800 | **49.2%**\*\* |
| **OSPTrack** (npm, from log) | [Zenodo](https://zenodo.org/records/14197378) | 2,316 | 13 | — |

**Total IOC coverage: 11,291/11,291 (100%)** against the DataDog dataset.

\*\* OSPTrack contains both malicious AND benign packages (~20% malicious per paper). The 800 matched PyPI packages represent ~49% of the estimated malicious subset. The remaining gap is because OSPTrack sources packages from OSSF package-analysis (BigQuery), which uses different naming than the DataDog dataset. The two datasets are complementary, not identical.

OSSF cross-reference rates are lower because the DataDog dataset includes packages that predate OSSF's MAL-* advisory system. Both datasets are complementary — Guard Proxy uses DataDog as its primary IOC source.

### Static Analysis Detection Rate

Pattern-matching benchmarks against public rule sets and taxonomies:

| Benchmark | Source | Detected | Rate |
|---|---|---|---|
| **GuardDog rules** (npm + PyPI) | [DataDog](https://github.com/DataDog/guarddog) | 28/28 | **100%** |
| **GuardDog rules** (Go) | [DataDog](https://github.com/DataDog/guarddog) | 5/5 | **100%** |
| **GuardDog rules** (RubyGems) | [DataDog](https://github.com/DataDog/guarddog) | 7/7 | **100%** |
| **BKC attack taxonomy** | [Springer/Uni Bonn](https://arxiv.org/abs/2005.09535) | 12/12 | **100%** |
| **OSSF attack patterns** | [OpenSSF](https://github.com/ossf/malicious-packages) | 18/18 | **100%** |
| **OSPTrack categories** | [Zenodo/arXiv](https://arxiv.org/html/2411.14829v1) | 20/20 | **100%** |
| Real-world incidents (2024-2026) | Documented CVEs | 23/23 | **100%** |
| Go attack vectors | Known patterns\* | 10/10 | **100%** |
| Cargo attack vectors | Known patterns\* | 8/8 | **100%** |
| Adversarial evasion techniques | Internal | 35/35 | **100%** |

\* No standardized Go/Cargo-specific supply chain benchmark exists yet. Tests are based on real incidents (BoltDB typosquat, faster_log, evm-units) and known attack vectors.

### False Positive Rate

| Registry | Top Packages Tested | False Positives |
|---|---|---|
| npm | 34 | **0** |
| PyPI | 34 | **0** |
| RubyGems | 32 | **0** |
| Go | 20 | **0** |
| Cargo | 15 | **0** |

### Detection Categories (MITRE ATT&CK T1195)

Install-time execution, credential theft, network exfiltration, code obfuscation, process execution, file system manipulation, persistence mechanisms, typosquatting, cryptomining, Unicode steganography, time-bombs, reachability analysis, license compliance, and more.

Full details: [docs/](docs/)

## What Guard Proxy Does NOT Do

Transparency matters. Here's what you should know:

- **Not a CVE scanner** — Use `npm audit` / `pip-audit` alongside Guard Proxy for known vulnerability checking
- **No sandbox/dynamic analysis** — Detection is static + LLM-based, not runtime execution
- **Intra-file reachability only** — Call graph analysis is limited to single-file scope (cross-file requires LLM tier)
- **4 registries only** — npm, PyPI, RubyGems, Go. Cargo, Maven planned for future releases

Guard Proxy is designed to **complement** existing tools, not replace them.

## Disclaimer

Guard Proxy is provided as a security aid and **does not guarantee complete protection** against supply chain attacks. No automated tool can detect all malicious packages. Guard Proxy may produce both false positives (blocking safe packages) and false negatives (allowing malicious packages through).

This tool is **not a substitute** for a comprehensive security strategy including code review, dependency pinning, reproducible builds, and organizational security policies.

Guard Proxy is provided "as is" without warranty of any kind. See the [LICENSE](LICENSE) file for full terms. The authors and contributors are not liable for any damages resulting from the use of this software, including but not limited to security incidents arising from packages that were not detected as malicious.

## IOC Database

Guard Proxy integrates with the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (22,189+ human-verified malicious packages).

```bash
guard-proxy sync-ioc    # Syncs 11,000+ known malicious packages
```

Automated weekly sync available via GitHub Actions (see `.github/workflows/weekly-ioc-sync.yml`).

## SBOM Output

Guard Proxy generates [CycloneDX 1.6](https://cyclonedx.org/) SBOMs for every scanned package, including scan verdicts and scanner details.

```bash
guard-proxy sbom --file sbom.json
```

## Roadmap

- [x] **Go module support** (proxy.golang.org) — v2.0.0
- [x] **Dashboard UI** (scan history visualization) — v2.0.0
- [x] **DevContainer integration** (one-click setup) — v2.0.0
- [ ] **Reachability analysis** (extend AST to call-graph traversal)
- [ ] **Cargo (Rust) support**
- [ ] **YARA rule marketplace** (community-contributed rules)
- [ ] **Multi-registry single port** (path-based routing)
- [ ] **Maven (Java) support**

## Documentation

See [docs/](docs/) for detailed documentation (English + Japanese).

- [Architecture](docs/ARCHITECTURE.md)
- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md)
- [Design Decisions](docs/DESIGN_DECISIONS.md)
- [Configuration Reference](docs/CONFIG_REFERENCE.md)
- [LLM Setup Guide](docs/LLM_SETUP_GUIDE.md)

## Third-Party Notices

Guard Proxy uses data from [DataDog](https://github.com/DataDog/malicious-software-packages-dataset) (Apache-2.0), [OSV.dev](https://osv.dev/) (Apache-2.0), [deps.dev](https://deps.dev/) (CC-BY 4.0), and benchmarks against the [BKC dataset](https://arxiv.org/abs/2005.09535) (academic citation). Detection categories are aligned to [MITRE ATT&CK®](https://attack.mitre.org/) T1195. SBOM output uses [CycloneDX](https://cyclonedx.org/) format.

Full attribution: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to add new detection patterns.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md). **Do not open a public issue for security vulnerabilities.**

## License

[MIT](LICENSE) — Copyright (c) 2026 tokimoa
