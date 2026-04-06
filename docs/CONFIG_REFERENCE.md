# Guard Proxy - Configuration Reference

> Japanese version: [CONFIG_REFERENCE_ja.md](CONFIG_REFERENCE_ja.md)

All settings are managed via environment variables or a `.env` file.

## Application Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `APP_NAME` | str | `Guard Proxy` | Application name |
| `DEBUG` | bool | `false` | Debug mode |
| `ENVIRONMENT` | str | `development` | Runtime environment (development / staging / production) |
| `LOG_LEVEL` | str | `INFO` | Log level (DEBUG / INFO / WARNING / ERROR) |
| `LOG_FORMAT` | str | `text` | Log format (text / json) |

## Proxy Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `NPM_PROXY_PORT` | int | `4873` | npm proxy listening port |
| `NPM_UPSTREAM_URL` | str | `https://registry.npmjs.org` | npm upstream registry URL |
| `PYPI_PROXY_PORT` | int | `4874` | PyPI proxy listening port |
| `PYPI_UPSTREAM_URL` | str | `https://pypi.org` | PyPI upstream registry URL |
| `RUBYGEMS_PROXY_PORT` | int | `4875` | RubyGems proxy listening port |
| `RUBYGEMS_UPSTREAM_URL` | str | `https://rubygems.org` | RubyGems upstream registry URL |
| `GO_PROXY_PORT` | int | `4876` | Go module proxy listening port |
| `GO_UPSTREAM_URL` | str | `https://proxy.golang.org` | Go module upstream proxy URL |
| `ADMIN_API_PORT` | int | `8100` | Admin API listening port |

## Cooldown Gate Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `COOLDOWN_DAYS` | int | `7` | Minimum waiting period in days since package publication |
| `COOLDOWN_ACTION` | str | `warn` | Action on cooldown violation (`warn` / `deny`) |

## Static Analysis Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `STATIC_ANALYSIS_ENABLED` | bool | `true` | Enable/disable static analysis |
| `STATIC_ANALYSIS_SEVERITY_THRESHOLD` | str | `medium` | Minimum severity to report (`low` / `medium` / `high` / `critical`) |

## LLM Judge Settings

### Common Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `LLM_ENABLED` | bool | `false` | Enable/disable LLM Judge |
| `LLM_STRATEGY` | str | `local_first` | Execution strategy (`local_first` / `cloud_only` / `local_only` / `consensus`) |
| `LLM_MAX_TOKENS` | int | `4096` | Maximum token count for responses |
| `LLM_MAX_FILE_SIZE_KB` | int | `512` | Maximum file size for scan targets |

### Escalation Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `LOCAL_CONFIDENCE_THRESHOLD` | float | `0.8` | Escalate to cloud if local LLM confidence is below this value |
| `OBFUSCATION_CLOUD_THRESHOLD` | float | `0.7` | Skip local LLM and send directly to cloud if obfuscation score is at or above this value |

### Local LLM (Ollama) Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `OLLAMA_ENABLED` | bool | `true` | Enable/disable Ollama provider |
| `OLLAMA_BASE_URL` | str | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | str | `qwen3.5:9b` | Model name to use. Recommended: `qwen3.5:9b`, `gemma4:26b`, `qwen3-coder:30b`. See [LLM Setup Guide](LLM_SETUP_GUIDE.md) |
| `OLLAMA_TIMEOUT_SECONDS` | int | `60` | Inference timeout (generous for local inference) |

### Cloud LLM -- Anthropic (Primary) Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | str | *(none)* | Claude API key |
| `ANTHROPIC_MODEL` | str | `claude-sonnet-4-6` | Model to use |
| `ANTHROPIC_TIMEOUT_SECONDS` | int | `30` | API call timeout |

### Cloud LLM -- OpenAI (Fallback) Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | str | *(none)* | OpenAI API key |
| `OPENAI_MODEL` | str | `gpt-5.4` | Model to use |
| `OPENAI_TIMEOUT_SECONDS` | int | `30` | API call timeout |

### Cloud LLM -- OpenAI-Compatible (Custom) Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `CUSTOM_LLM_BASE_URL` | str | *(none)* | Custom OpenAI-compatible server URL (e.g., vLLM) |
| `CUSTOM_LLM_API_KEY` | str | *(none)* | Custom server API key |
| `CUSTOM_LLM_MODEL` | str | *(none)* | Model name to use |

### Cost Control

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `CLOUD_DAILY_LIMIT` | int | `100` | Daily cloud API call limit |
| `CLOUD_MONTHLY_BUDGET_USD` | float | `20.0` | Monthly cloud API budget cap (USD) |

## Decision Engine Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `DECISION_MODE` | str | `warn` | Decision mode (`warn`: warnings only / `enforce`: blocking enabled) |
| `WARN_THRESHOLD` | float | `0.3` | Threshold for quarantine verdict |
| `DENY_THRESHOLD` | float | `0.7` | Threshold for deny verdict |
| `COOLDOWN_WEIGHT` | float | `0.3` | Weight for cooldown scanner |
| `STATIC_ANALYSIS_WEIGHT` | float | `0.4` | Weight for static analysis scanner |
| `LLM_WEIGHT` | float | `0.3` | Weight for LLM Judge scanner |

## Cache Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `CACHE_DB_PATH` | str | `./data/cache.db` | Cache database file path |
| `CACHE_TTL_HOURS` | int | `168` | Cache TTL in hours (168h = 7 days) |
| `CACHE_MAX_SIZE_MB` | int | `500` | Maximum cache database size (MB) |

## Database Settings

| Environment Variable | Type | Default | Description |
|---|---|---|---|
| `DB_PATH` | str | `./data/guard_proxy.db` | Main database file path |

---

## Usage Examples

### Minimal Configuration (No LLM)
```bash
# .env
COOLDOWN_DAYS=7
DECISION_MODE=warn
# LLM_ENABLED=false is the default, so no LLM-related settings are needed
```

### Local LLM Only (Completely Free)
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:9b

# Pull the model beforehand
# ollama pull qwen3.5:9b
```

### Local-First + Cloud Fallback (Recommended)
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=local_first
OLLAMA_MODEL=qwen3.5:9b
ANTHROPIC_API_KEY=sk-ant-xxxxx
LOCAL_CONFIDENCE_THRESHOLD=0.8
CLOUD_DAILY_LIMIT=100
```

### Cloud Only (No Ollama)
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-xxxxx
ANTHROPIC_MODEL=claude-sonnet-4-6
# Fallback
OPENAI_API_KEY=sk-xxxxx
OPENAI_MODEL=gpt-5.4
```

### High-Security Environment (Consensus)
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=consensus
OLLAMA_MODEL=qwen3.5:9b
ANTHROPIC_API_KEY=sk-ant-xxxxx
DECISION_MODE=enforce
COOLDOWN_DAYS=14
```

### Strict Mode (For CI/CD)
```bash
# .env
COOLDOWN_DAYS=14
DECISION_MODE=enforce
STATIC_ANALYSIS_SEVERITY_THRESHOLD=low
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-xxxxx
CLOUD_DAILY_LIMIT=500
```

### Team Server
```bash
# .env
NPM_PROXY_PORT=4873
PYPI_PROXY_PORT=4874
RUBYGEMS_PROXY_PORT=4875
ADMIN_API_PORT=8100
COOLDOWN_DAYS=7
DECISION_MODE=enforce
LLM_ENABLED=true
LLM_STRATEGY=local_first
OLLAMA_BASE_URL=http://gpu-server.internal:11434
OLLAMA_MODEL=qwen3.5:9b
ANTHROPIC_API_KEY=sk-ant-xxxxx
CLOUD_DAILY_LIMIT=200
CLOUD_MONTHLY_BUDGET_USD=50.0
```

### Custom Server (vLLM, etc.)
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
CUSTOM_LLM_BASE_URL=http://vllm-server.internal:8000/v1
CUSTOM_LLM_MODEL=Qwen/Qwen3.5-32B
```

---

## Developer-Side Configuration

### npm
```ini
# Project .npmrc
registry=http://localhost:4873
```

### pip
```ini
# ~/.config/pip/pip.conf (macOS/Linux)
[global]
index-url = http://localhost:4874/simple/
trusted-host = localhost
```

### uv
```bash
# Set via environment variable
UV_INDEX_URL=http://localhost:4874/simple/
```

### gem
```bash
# gem source configuration
gem install sinatra --source http://localhost:4875
```

### Bundler (Recommended)
```bash
# Mirror setting (routes all traffic through proxy without modifying Gemfile)
bundle config set --global mirror.https://rubygems.org http://localhost:4875
```

### Go
```bash
# Set via environment variables
export GOPROXY=http://localhost:4876,direct
export GONOSUMCHECK=*
```

---

## Auto-Detection Behavior

At startup, Guard Proxy automatically detects LLM provider availability.

```
Startup checks:
  1. Connect to OLLAMA_BASE_URL -> verify Ollama is running
  2. Verify OLLAMA_MODEL has been pulled
  3. Check if ANTHROPIC_API_KEY is configured
  4. Check if OPENAI_API_KEY is configured

Automatic behavior based on results:
  Ollama OK + Cloud OK -> follow LLM_STRATEGY setting
  Ollama OK + Cloud NG -> auto-switch to local_only (with warning)
  Ollama NG + Cloud OK -> auto-switch to cloud_only
  Ollama NG + Cloud NG -> disable LLM (Static Analysis only, with warning)
```
