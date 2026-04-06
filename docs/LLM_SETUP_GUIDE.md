# LLM Setup Guide

> Japanese version: [LLM_SETUP_GUIDE_ja.md](LLM_SETUP_GUIDE_ja.md)

Guard Proxy works without an LLM, but enabling one improves detection accuracy for **obfuscated attack code** and **unknown attack patterns**.

---

## What LLM Adds

| | Without LLM | With LLM |
|---|---|---|
| Known attack patterns (base64+eval, C2 comms, etc.) | ✅ Detected | ✅ Detected |
| IOC (known malicious packages) | ✅ Instant block | ✅ Instant block |
| Typosquatting | ✅ Detected | ✅ Detected |
| Variable indirection (`const e = eval; e(code)`) | ✅ AST analysis | ✅ AST + LLM |
| **Complex obfuscation** (XOR + multi-stage encoding) | ⚠️ Partial | ✅ LLM judges by context |
| **Unknown attack patterns** | ❌ Hard to detect | ✅ LLM infers intent |
| **"What does this code do?" explanation** | ❌ None | ✅ LLM records reasoning |

**Bottom line**: Without LLM, Guard Proxy detects **90%+ of attacks**. The LLM covers the remaining 10% — the "gray zone" requiring human-level judgment.

---

## Three Options

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Option A: No LLM (Simplest)                                    │
│  → Works immediately after install. No extra setup.             │
│  → Detection accuracy: ★★★★☆                                   │
│                                                                 │
│  Option B: Local LLM (Ollama) (Recommended)                     │
│  → Free. No data leaves your machine.                           │
│  → Requires: 8GB+ RAM + Ollama installed                        │
│  → Detection accuracy: ★★★★★                                   │
│                                                                 │
│  Option C: Cloud LLM (Claude / GPT)                             │
│  → Highest accuracy. Requires API key. Pay-per-use.             │
│  → Estimated cost: $0.5–$5/month (typical developer usage)      │
│  → Detection accuracy: ★★★★★+                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Option A: No LLM

No configuration needed. `LLM_ENABLED=false` is the default.

```bash
uv sync
guard-proxy start
```

This alone activates the 12 fast-tier scanners (IOC, Advisory, Cooldown, Metadata (typosquatting), Maintainer, Static Analysis, Heuristics, AST, YARA, Reachability, License, Dependency).

> **Note**: License compliance scanning, Reachability analysis, and the YARA rule marketplace all work entirely without LLM. These features provide significant detection coverage at zero LLM cost.

---

## Option B: Local LLM (Ollama) — Recommended

### Step 1: Install Ollama

**macOS:**
```bash
brew install ollama
brew services start ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows:**
Download the installer from [https://ollama.com/download](https://ollama.com/download)

### Step 2: Download a Model

```bash
ollama pull qwen3.5:latest
```

**Download size**: ~5GB (first time only)
**Required memory**: 8GB RAM

> **Low on memory?** You can use a smaller model:
> ```bash
> ollama pull qwen3:4b     # 4B model, ~3GB, runs on 4GB RAM
> ```
> Detection accuracy will be slightly lower.

### Step 3: Configure Guard Proxy

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:latest
EOF
```

### Step 4: Start

```bash
guard-proxy start
```

If you see the following in the startup log, LLM is active:
```
LLM Judge enabled — tiered scanning active
```

### How It Works

```
Package download
    │
    ├─ Fast Tier (< 1 second): 12 scanners judge instantly
    │   → Clean & no install hooks → instant pass (LLM runs in background)
    │   → Suspicious patterns found → LLM analyzes synchronously
    │
    └─ Subsequent requests: cache hit (includes LLM result) → instant pass
```

**The first scan of a package may take a few seconds to tens of seconds**, but subsequent scans return instantly from cache.

### Troubleshooting

**"Ollama not running":**
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags
# If no response, start Ollama
ollama serve
```

**"Model not found":**
```bash
# Check downloaded models
ollama list
# Download if missing
ollama pull qwen3.5:latest
```

---

## Option C: Cloud LLM (Claude / GPT)

### Using Claude API (Anthropic)

1. Get an API key at [console.anthropic.com](https://console.anthropic.com/)
2. Configure:

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxx
EOF
```

### Adding GPT API (OpenAI) as Fallback

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=local_first
OLLAMA_MODEL=qwen3.5:latest
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxx
OPENAI_API_KEY=sk-xxxxxxxxxxxxx
EOF
```

With this configuration:
1. First, the local LLM (Ollama) judges the code
2. If confidence is low → escalates to Claude API
3. If Claude API is unavailable → falls back to GPT API
4. If all LLMs are unavailable → decides based on static analysis results only

### Cost Estimate

| Strategy | Monthly Cost | Description |
|---|---|---|
| `local_only` | **$0** | Ollama only. Just electricity |
| `local_first` | **$0.5–$2** | Mostly local. Only escalation calls are billed |
| `cloud_only` | **$5–$15** | All cloud LLM |

---

## Four Strategies (LLM_STRATEGY)

| Strategy | Behavior | Best For |
|---|---|---|
| `local_only` | Ollama only | Offline environments, minimum cost |
| `local_first` | Ollama → cloud if confidence is low | **Recommended**. Balance of cost and accuracy |
| `cloud_only` | Claude/GPT only | When you don't want to install Ollama |
| `consensus` | Both local + cloud → consensus verdict | High-security environments |

---

## Choosing a Model

### Recommended Models (as of April 2026)

| Model | Parameters | Size | RAM | Code Analysis | JSON Stability | Command |
|---|---|---|---|---|---|---|
| **`qwen3.5:latest`** | 8B | 5GB | 8GB | ★★★★★ | ◎ Stable | `ollama pull qwen3.5:latest` |
| **`gemma4:26b`** | 26B (MoE, 4B active) | 18GB | 18GB | ★★★★★ | ◎ Stable | `ollama pull gemma4:26b` |
| **`qwen3-coder:30b`** | 30B (MoE, 3.3B active) | 19GB | 20GB | ★★★★★+ | ◎ Stable | `ollama pull qwen3-coder:30b` |
| `mistral-small3.2:24b` | 24B | 15GB | 18GB | ★★★★☆ | ◎ Stable | `ollama pull mistral-small3.2:24b` |
| `phi4:14b` | 14B | 9GB | 10GB | ★★★★☆ | ○ Good | `ollama pull phi4:14b` |
| `gemma4:e4b` | 4B | 10GB | 8GB | ★★★★☆ | ○ Good | `ollama pull gemma4:e4b` |

### Lightweight Models (Limited Memory)

| Model | Parameters | Size | RAM | Code Analysis | Command |
|---|---|---|---|---|---|
| `qwen3.5:latest` (8B) | 8B | 5GB | 8GB | ★★★★★ | `ollama pull qwen3.5:latest` |
| `gemma4:e4b` | 4B | 10GB | 8GB | ★★★★☆ | `ollama pull gemma4:e4b` |
| `qwen3:4b` | 4B | 3GB | 4GB | ★★★☆☆ | `ollama pull qwen3:4b` |

### Which One Should I Pick?

- **Not sure → `qwen3.5:latest`** (Default recommendation. Runs on 8GB RAM, best balance of accuracy, speed, and stability)
- **32GB RAM → `gemma4:26b` or `qwen3-coder:30b`** (MoE architecture means effective 4B/3.3B inference speed. `qwen3-coder` is best for code analysis)
- **16–18GB RAM → `mistral-small3.2:24b`** (Mature structured output support, stability-focused)
- **Only 8GB RAM → `qwen3.5:latest`** (Optimal choice for this constraint)
- **Only 4GB RAM → `qwen3:4b`** (Lower accuracy, but still better than no LLM)

> **Note**: MoE models (gemma4:26b, qwen3-coder:30b) have large parameter counts but only activate a fraction during inference, making them fast.
>
> **Models to avoid**: DeepSeek R1 series — `<think>` blocks break JSON structured output, incompatible with Guard Proxy. Llama 4 — 67GB+ download, too large for consumer hardware.

### Compatibility

Guard Proxy uses Ollama's **OpenAI-compatible API** (`/v1/chat/completions`) and **structured output** (`format: json_schema`). Any model that supports these two features will work. To use a model not listed above, simply set the model name in `OLLAMA_MODEL`.

---

## Verification

Commands to verify your setup:

```bash
# Check Ollama status
guard-proxy status

# Test scan (verifies LLM is working)
guard-proxy scan express

# Check logs
# If you see this at startup, LLM is active:
# "LLM Judge enabled — tiered scanning active"
```
