# Guard Proxy - 設定リファレンス

全ての設定は環境変数または`.env`ファイルで管理します。

## アプリケーション設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `APP_NAME` | str | `Guard Proxy` | アプリケーション名 |
| `DEBUG` | bool | `false` | デバッグモード |
| `ENVIRONMENT` | str | `development` | 実行環境 (development / staging / production) |
| `LOG_LEVEL` | str | `INFO` | ログレベル (DEBUG / INFO / WARNING / ERROR) |
| `LOG_FORMAT` | str | `text` | ログフォーマット (text / json) |

## プロキシ設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `NPM_PROXY_PORT` | int | `4873` | npmプロキシのリスニングポート |
| `NPM_UPSTREAM_URL` | str | `https://registry.npmjs.org` | npm上流レジストリURL |
| `PYPI_PROXY_PORT` | int | `4874` | PyPIプロキシのリスニングポート |
| `PYPI_UPSTREAM_URL` | str | `https://pypi.org` | PyPI上流レジストリURL |
| `RUBYGEMS_PROXY_PORT` | int | `4875` | RubyGemsプロキシのリスニングポート |
| `RUBYGEMS_UPSTREAM_URL` | str | `https://rubygems.org` | RubyGems上流レジストリURL |
| `ADMIN_API_PORT` | int | `8100` | 管理APIのリスニングポート |

## クールダウンゲート設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `COOLDOWN_DAYS` | int | `7` | 公開からの最低待機日数 |
| `COOLDOWN_ACTION` | str | `warn` | cooldown違反時の動作 (`warn` / `deny`) |

## 静的解析設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `STATIC_ANALYSIS_ENABLED` | bool | `true` | 静的解析の有効/無効 |
| `STATIC_ANALYSIS_SEVERITY_THRESHOLD` | str | `medium` | 報告する最低重要度 (`low` / `medium` / `high` / `critical`) |

## LLM Judge 設定

### 共通設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `LLM_ENABLED` | bool | `false` | LLM Judgeの有効/無効 |
| `LLM_STRATEGY` | str | `local_first` | 実行戦略 (`local_first` / `cloud_only` / `local_only` / `consensus`) |
| `LLM_MAX_TOKENS` | int | `4096` | レスポンスの最大トークン数 |
| `LLM_MAX_FILE_SIZE_KB` | int | `512` | スキャン対象ファイルの最大サイズ |

### エスカレーション設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `LOCAL_CONFIDENCE_THRESHOLD` | float | `0.8` | ローカルLLMのconfidenceがこの値未満ならクラウドにエスカレーション |
| `OBFUSCATION_CLOUD_THRESHOLD` | float | `0.7` | 難読化スコアがこの値以上ならローカルLLMをスキップしてクラウドに直接送信 |

### ローカルLLM（Ollama）設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `OLLAMA_ENABLED` | bool | `true` | Ollamaプロバイダーの有効/無効 |
| `OLLAMA_BASE_URL` | str | `http://localhost:11434` | OllamaサーバーのURL |
| `OLLAMA_MODEL` | str | `qwen3.5:9b` | 使用するモデル名。推奨: `qwen3.5:9b`, `gemma4:26b`, `qwen3-coder:30b`。[LLMセットアップガイド](LLM_SETUP_GUIDE_ja.md)参照 |
| `OLLAMA_TIMEOUT_SECONDS` | int | `60` | 推論タイムアウト（ローカルは余裕を持たせる） |

### クラウドLLM — Anthropic（プライマリ）設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | str | *(なし)* | Claude API キー |
| `ANTHROPIC_MODEL` | str | `claude-sonnet-4-6` | 使用するモデル |
| `ANTHROPIC_TIMEOUT_SECONDS` | int | `30` | API呼び出しタイムアウト |

### クラウドLLM — OpenAI（フォールバック）設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `OPENAI_API_KEY` | str | *(なし)* | OpenAI API キー |
| `OPENAI_MODEL` | str | `gpt-5.4` | 使用するモデル |
| `OPENAI_TIMEOUT_SECONDS` | int | `30` | API呼び出しタイムアウト |

### クラウドLLM — OpenAI互換（カスタム）設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `CUSTOM_LLM_BASE_URL` | str | *(なし)* | カスタムOpenAI互換サーバーのURL（vLLM等） |
| `CUSTOM_LLM_API_KEY` | str | *(なし)* | カスタムサーバーのAPIキー |
| `CUSTOM_LLM_MODEL` | str | *(なし)* | 使用するモデル名 |

### コスト制御

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `CLOUD_DAILY_LIMIT` | int | `100` | クラウドAPI日次呼び出し上限 |
| `CLOUD_MONTHLY_BUDGET_USD` | float | `20.0` | クラウドAPI月次予算上限（USD） |

## 判定エンジン設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `DECISION_MODE` | str | `warn` | 判定モード (`warn`: 警告のみ / `enforce`: ブロック有効) |
| `WARN_THRESHOLD` | float | `0.3` | quarantine判定の閾値 |
| `DENY_THRESHOLD` | float | `0.7` | deny判定の閾値 |
| `COOLDOWN_WEIGHT` | float | `0.3` | クールダウンスキャナの重み |
| `STATIC_ANALYSIS_WEIGHT` | float | `0.4` | 静的解析スキャナの重み |
| `LLM_WEIGHT` | float | `0.3` | LLM Judgeスキャナの重み |

## キャッシュ設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `CACHE_DB_PATH` | str | `./data/cache.db` | キャッシュDBファイルパス |
| `CACHE_TTL_HOURS` | int | `168` | キャッシュの有効期間（時間）※168h = 7日 |
| `CACHE_MAX_SIZE_MB` | int | `500` | キャッシュDBの最大サイズ（MB） |

## データベース設定

| 環境変数 | 型 | デフォルト | 説明 |
|---|---|---|---|
| `DB_PATH` | str | `./data/guard_proxy.db` | メインDBファイルパス |

---

## 使用例

### 最小構成（LLMなし）
```bash
# .env
COOLDOWN_DAYS=7
DECISION_MODE=warn
# LLM_ENABLED=false がデフォルトなのでLLM関連設定は不要
```

### ローカルLLMのみ（完全無料）
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:9b

# 事前にモデルをpullしておく
# ollama pull qwen3.5:9b
```

### ローカル優先 + クラウドフォールバック（推奨構成）
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=local_first
OLLAMA_MODEL=qwen3.5:9b
ANTHROPIC_API_KEY=sk-ant-xxxxx
LOCAL_CONFIDENCE_THRESHOLD=0.8
CLOUD_DAILY_LIMIT=100
```

### クラウドのみ（Ollama未使用）
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-xxxxx
ANTHROPIC_MODEL=claude-sonnet-4-6
# フォールバック用
OPENAI_API_KEY=sk-xxxxx
OPENAI_MODEL=gpt-5.4
```

### 高セキュリティ環境（consensus）
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=consensus
OLLAMA_MODEL=qwen3.5:9b
ANTHROPIC_API_KEY=sk-ant-xxxxx
DECISION_MODE=enforce
COOLDOWN_DAYS=14
```

### 厳格モード（CI/CD向け）
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

### チームサーバー
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

### vLLM等のカスタムサーバー使用
```bash
# .env
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
CUSTOM_LLM_BASE_URL=http://vllm-server.internal:8000/v1
CUSTOM_LLM_MODEL=Qwen/Qwen3.5-32B
```

---

## 開発者側の設定

### npm
```ini
# プロジェクトの .npmrc
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
# 環境変数で設定
UV_INDEX_URL=http://localhost:4874/simple/
```

### gem
```bash
# gem source設定
gem install sinatra --source http://localhost:4875
```

### bundler（推奨）
```bash
# mirror設定（Gemfile変更不要で全トラフィックをプロキシ経由）
bundle config set --global mirror.https://rubygems.org http://localhost:4875
```

---

## 自動検出動作

Guard Proxy起動時に、LLMプロバイダーの可用性を自動検出します。

```
起動時チェック:
  1. OLLAMA_BASE_URL に接続 → Ollamaが起動中か確認
  2. OLLAMA_MODEL がpull済みか確認
  3. ANTHROPIC_API_KEY が設定されているか確認
  4. OPENAI_API_KEY が設定されているか確認

結果に応じた自動動作:
  Ollama OK + Cloud OK → LLM_STRATEGY の設定に従う
  Ollama OK + Cloud NG → local_only に自動切替（警告表示）
  Ollama NG + Cloud OK → cloud_only に自動切替
  Ollama NG + Cloud NG → LLM無効化（Static Analysisのみ、警告表示）
```
