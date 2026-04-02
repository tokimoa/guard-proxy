# Guard Proxy - アーキテクチャ設計書

## 概要

Guard Proxyは、npm / PyPI / RubyGemsのサプライチェーン攻撃から開発者を保護するセキュリティプロキシです。
開発者の`npm install` / `pip install` / `gem install`を透過的にインターセプトし、パッケージの安全性を検証してからダウンロードを許可します。

## 背景と動機

2026年3月に発生した以下のサプライチェーン攻撃を契機として設計されました：

- **axios@1.14.1 / 0.30.4** — npmアカウント乗っ取りによるRAT配布（2026/3/31）
- **litellm@1.82.7 / 1.82.8** — CI/CD汚染経由のクレデンシャルスティーラー（2026/3/24）

これらの攻撃は`postinstall`スクリプトや`.pth`ファイルを通じて**install時点で即座に実行**され、開発マシンのクレデンシャルを窃取するものでした。

## システム構成図

```
開発者 (npm install / pip install)
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│                     Guard Proxy                           │
│                                                          │
│  ┌──────────┐                                            │
│  │  Cache    │── ヒット → 即座にallow/deny                │
│  │ (SQLite)  │                                            │
│  └────┬─────┘                                            │
│       │ ミス                                              │
│       ▼                                                  │
│  ┌──────────────────┐                                    │
│  │ Registry Client   │── 上流からメタデータ取得            │
│  │ (npm / PyPI API)  │   (公開日, 作者, 依存関係)         │
│  └────┬─────────────┘                                    │
│       ▼                                                  │
│  ┌──────────────────────────────────────────────────┐    │
│  │              Scan Pipeline                        │    │
│  │                                                  │    │
│  │  ┌────────────┐  ┌──────────────┐                │    │
│  │  │  Cooldown   │→│   Static     │                │    │
│  │  │   Gate      │  │  Analysis    │                │    │
│  │  └────────────┘  └──────┬───────┘                │    │
│  │                         │ warn以上                │    │
│  │                         ▼                        │    │
│  │  ┌──────────────────────────────────────────┐    │    │
│  │  │         LLM Judge Router                  │    │    │
│  │  │                                          │    │    │
│  │  │  strategy: local_first | cloud_only      │    │    │
│  │  │           | local_only | consensus       │    │    │
│  │  │                                          │    │    │
│  │  │  ┌──────────┐ ┌─────────┐ ┌──────────┐  │    │    │
│  │  │  │  Local    │ │ Claude  │ │   GPT    │  │    │    │
│  │  │  │ (Ollama)  │ │  API    │ │   API    │  │    │    │
│  │  │  │ Qwen3.5   │ │ Sonnet  │ │   5.4    │  │    │    │
│  │  │  │ etc.      │ │         │ │          │  │    │    │
│  │  │  │ $0/無制限  │ │ 低コスト │ │ 低コスト  │  │    │    │
│  │  │  └──────────┘ └─────────┘ └──────────┘  │    │    │
│  │  │           │         │          │         │    │    │
│  │  │           └─────────┴──────────┘         │    │    │
│  │  │                     │                    │    │    │
│  │  │           判定結果統合 + エスカレーション    │    │    │
│  │  └─────────────────────┬────────────────────┘    │    │
│  └────────────────────────┴─────────────────────────┘    │
│                            ▼                              │
│  ┌──────────────────────────────────────────────────┐    │
│  │              Decision Engine                      │    │
│  │  重み付きスコアリング → allow/deny/quarantine       │    │
│  └────┬─────────────────────────────────────────────┘    │
│       │                                                  │
│       ├─ allow      → 上流レスポンスを中継                │
│       ├─ quarantine → 警告ログ + 中継 or ブロック         │
│       └─ deny       → 403エラー + 理由説明               │
│                                                          │
│  ┌──────────┐  ┌──────────────┐                          │
│  │ Audit Log │  │ Admin API    │                          │
│  │ (SQLite)  │  │ (FastAPI)    │                          │
│  └──────────┘  └──────────────┘                          │
└──────────────────────────────────────────────────────────┘
    │
    ▼
上流レジストリ (registry.npmjs.org / pypi.org / rubygems.org)
```

## コンポーネント詳細

### 1. Proxy Layer (`app/proxy/`)

HTTPリクエストのインターセプトと上流レジストリへの中継を担当します。

| ファイル | 責務 |
|---|---|
| `base.py` | 抽象プロキシ基底クラス。共通のリクエスト中継ロジック |
| `npm.py` | npm registry APIプロトコルの実装。tarball URLのリダイレクト処理を含む |
| `pypi.py` | PyPI Simple API / JSON APIプロトコルの実装 |
| `rubygems.py` | RubyGems Compact Index / gem download プロトコルの実装 |
| `middleware.py` | リクエストロギング、タイムアウト制御等の共通ミドルウェア |

#### npm プロキシの通信フロー

```
1. GET /<package>           → パッケージメタデータ取得
2. GET /<package>/-/<tarball> → tarballダウンロード（ここでスキャン）
```

#### PyPI プロキシの通信フロー

```
1. GET /simple/<package>/     → パッケージインデックス取得
2. GET /packages/<path>.whl   → whl/sdistダウンロード（ここでスキャン）
```

#### RubyGems プロキシの通信フロー

```
1. GET /info/<gem>             → Compact Indexメタデータ取得（パススルー）
2. GET /versions               → バージョンリスト（パススルー）
3. GET /gems/<gem>-<ver>.gem   → gemダウンロード（ここでスキャン）
```

### 2. Scanner Layer (`app/scanners/`)

3種類のスキャナが共通の`ScannerProtocol`を実装します。

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

パッケージの公開日を検証し、N日未満であれば警告/ブロックします。

- **入力**: パッケージメタデータ（公開日）
- **判定**: `公開からの経過日数 < COOLDOWN_DAYS` → fail / warn
- **設定**: `COOLDOWN_DAYS`（デフォルト: 7日）, `COOLDOWN_ACTION`（warn / deny）

#### 2b. Static Analysis (`static_analysis.py`)

パッケージのinstallスクリプト等に対してパターンマッチングを実行します。

**npmスキャン対象:**
- `package.json` → `scripts.postinstall`, `scripts.preinstall`, `scripts.install`
- スクリプトファイル本体

**PyPIスキャン対象:**
- `setup.py` → `cmdclass`, install hooks
- `*.pth` ファイル
- `__init__.py`（インポート時実行コード）

**RubyGemsスキャン対象:**
- `extconf.rb` → ネイティブ拡張ビルドスクリプト（install時実行）
- `ext/**/*.rb` → ネイティブ拡張ソース
- `rubygems_plugin.rb` → gem読み込み時に自動実行
- `Rakefile` → ビルドタスク定義

**検出パターン:**
- 環境変数の一括取得 (`os.environ`, `process.env`)
- クレデンシャルファイルへのアクセス (`~/.ssh`, `~/.aws`)
- Base64デコード → eval/exec
- 外部ドメインへのHTTP通信
- プロセスの永続化 (systemd, launchd, crontab)
- 難読化されたコード

**デオブフスケート前処理:**
静的解析は単純なパターンマッチに加え、LLM Judgeの精度を高めるための前処理も担当します。

- Base64エンコード文字列の検出とデコード
- `eval`/`exec` の引数展開
- 難読化スコアの算出（高スコアの場合、ローカルLLMをスキップしてクラウドに直接エスカレーション）

#### 2c. LLM-as-a-Judge (`app/scanners/llm/`)

マルチプロバイダー対応のLLM判定エンジン。静的解析では判断困難なケースを精査します。

##### アーキテクチャ

```
┌──────────────────────────────────────────────────────────┐
│                    LLM Judge Router                       │
│                    (llm/judge.py)                         │
│                                                          │
│  strategy に基づきプロバイダーを選択・実行                    │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │              LLMProvider (Protocol)                 │  │
│  │              (llm/provider.py)                      │  │
│  │                                                    │  │
│  │  judge(prompt, schema) -> JudgeResult              │  │
│  │  is_available() -> bool                            │  │
│  │  provider_name -> str                              │  │
│  └────────────────────────────────────────────────────┘  │
│       ▲              ▲              ▲                    │
│       │              │              │                    │
│  ┌────┴─────┐  ┌─────┴─────┐  ┌────┴─────┐             │
│  │  Ollama   │  │ Anthropic │  │  OpenAI  │             │
│  │ Provider  │  │ Provider  │  │ Provider │             │
│  │           │  │           │  │          │             │
│  │ OpenAI互換│  │ anthropic │  │ openai   │             │
│  │ API経由   │  │ SDK経由   │  │ SDK経由  │             │
│  │           │  │           │  │          │             │
│  │ 構造化出力:│  │ tool_use  │  │ response │             │
│  │ format=   │  │ による    │  │ _format  │             │
│  │ json_schema│ │ JSON出力  │  │ による   │             │
│  └───────────┘  └───────────┘  └──────────┘             │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Prompt Builder (llm/prompt_builder.py)    │  │
│  │           プロバイダー共通のプロンプト構築              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Deobfuscator (llm/deobfuscator.py)       │  │
│  │           Base64展開等の前処理                       │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

##### 実行戦略（Strategy）

| 戦略 | 動作 | ユースケース |
|---|---|---|
| `local_first` | ローカルLLMで判定 → confidence低ならクラウドにエスカレーション | **推奨デフォルト**。コスト最小化 |
| `cloud_only` | クラウドLLM（Claude/GPT）のみ使用 | ローカルLLM未設定の環境 |
| `local_only` | ローカルLLM（Ollama）のみ使用 | オフライン環境、完全無料運用 |
| `consensus` | ローカル+クラウド両方実行し、合意で判定 | 高セキュリティ環境 |

##### `local_first` 戦略のフロー

```
Static Analysisから疑わしいスクリプトを受信
    │
    ▼
Deobfuscator で前処理（Base64展開等）
    │
    ▼
難読化スコアを確認
    │
    ├─ 高い → クラウドLLMに直接送信（小規模モデルでは精度不足の可能性）
    │
    └─ 低〜中 → ローカルLLM (Ollama) で判定
                    │
                    ├─ confidence ≥ 0.8 → 結果を採用（$0）
                    │
                    └─ confidence < 0.8 → クラウドLLMにエスカレーション
                                              │
                                              ├─ Anthropic (primary)
                                              │
                                              └─ OpenAI (fallback)
```

##### フォールバックチェーン

```
1. ローカルLLM (Ollama) が起動中 → 使用
2. Ollama未起動 or タイムアウト → クラウドプライマリ (Anthropic)
3. Anthropic API障害 → クラウドフォールバック (OpenAI)
4. 全LLM利用不可 → Static Analysisの結果のみで判定（degraded mode）
```

##### コスト試算

```
前提: 1日にnpm install で50パッケージを新規取得

Static Analysis → LLM呼び出し対象: 2〜3パッケージ (5%)

local_only:   $0/月
local_first:  月$0.5〜$2（エスカレーション分のみ）
cloud_only:   月$5〜$15
consensus:    月$5〜$15（local + cloud両方）
```

##### 対応プロバイダーとモデル

| プロバイダー | モデル例 | 構造化出力方式 | 特徴 |
|---|---|---|---|
| Ollama (ローカル) | **Qwen3.5-9B** (デフォルト), Gemma4-26B, Qwen3-Coder-30B, Mistral Small 3.2 | `format: json_schema` (GBNF文法ベース) | $0、Ollama対応モデルすべて |
| Anthropic (クラウド) | Claude Sonnet 4.6 | `tool_use` による構造化出力 | 高精度、低遅延 |
| OpenAI (クラウド) | GPT-5.4 | `response_format: json_schema` | 高精度、フォールバック用 |
| OpenAI互換 (汎用) | 任意 | OpenAI互換API | vLLM等のカスタムサーバー対応 |

> 詳細なモデル推奨とRAM要件は [LLMセットアップガイド](LLM_SETUP_GUIDE_ja.md) を参照。

### 3. Decision Engine (`app/decision/`)

各スキャナの結果を重み付きスコアリングで統合し、最終判定を下します。

```
最終スコア = Σ (scanner_weight × verdict_score × confidence)

verdict_score:
  pass = 0.0
  warn = 0.5
  fail = 1.0

判定:
  allow:      スコア < WARN_THRESHOLD (0.3)
  quarantine: WARN_THRESHOLD ≤ スコア < DENY_THRESHOLD (0.7)
  deny:       スコア ≥ DENY_THRESHOLD (0.7)
```

### 4. Registry Client (`app/registry/`)

上流レジストリAPI（npmjs.org / pypi.org / rubygems.org）との通信を担当します。

- パッケージメタデータ取得（公開日、作者、依存関係リスト）
- tarball / whl / .gem ファイルのダウンロード
- httpxベースの非同期HTTPクライアント
- 各レジストリ固有のAPIプロトコル対応（npm JSON API / PyPI Simple API / RubyGems Compact Index）

### 5. Database (`app/db/`)

SQLiteを使用し、以下のデータを永続化します。

| テーブル | 用途 |
|---|---|
| `scan_results` | スキャン結果キャッシュ（pkg名+version+hash → 判定結果） |
| `ioc_entries` | 既知のIOC（悪意あるパッケージ名、C2ドメイン/IP） |
| `audit_logs` | 全リクエストの監査ログ（判定結果、タイムスタンプ） |
| `llm_usage` | LLM使用量トラッキング（プロバイダー別、日次集計） |

### 6. CLI (`cli/`)

Typerベースのコマンドラインインターフェース。

```bash
guard-proxy start              # プロキシ起動
guard-proxy scan <pkg>         # 手動スキャン
guard-proxy config show        # 設定表示
guard-proxy cache list         # キャッシュ一覧
guard-proxy status             # ステータス確認
guard-proxy llm status         # LLMプロバイダー接続状況確認
guard-proxy llm test           # LLMプロバイダーの動作テスト
```

### 7. Admin API (`app/api/`)

プロキシの管理用REST API（FastAPI）。

- `GET /health` — ヘルスチェック
- `POST /scan` — 手動スキャン実行
- `GET /cache` — キャッシュ管理
- `GET /config` — 現在の設定確認
- `GET /llm/status` — LLMプロバイダー状態（各プロバイダーの可用性、日次使用量）

## ディレクトリ構成

```
guard-proxy/
├── app/                              # メインアプリケーション
│   ├── main.py                       # FastAPIアプリケーション起動
│   ├── core/                         # 設定管理, ロギング, 例外定義
│   ├── proxy/                        # npm/PyPI/RubyGemsプロキシエンジン
│   ├── scanners/                     # セキュリティスキャナ群
│   │   ├── patterns/                 # 悪意あるパターン定義
│   │   └── llm/                      # LLM Judge サブパッケージ
│   │       ├── judge.py              # LLM Judgeメインロジック（ルーター）
│   │       ├── provider.py           # LLMProvider 抽象基底クラス
│   │       ├── ollama_provider.py    # Ollama（ローカルLLM）プロバイダー
│   │       ├── anthropic_provider.py # Claude APIプロバイダー
│   │       ├── openai_provider.py    # GPT APIプロバイダー
│   │       ├── prompt_builder.py     # プロンプト構築（プロバイダー共通）
│   │       └── deobfuscator.py       # 前処理（Base64展開、難読化スコア算出）
│   ├── decision/                     # 判定エンジン
│   ├── registry/                     # レジストリAPIクライアント
│   ├── db/                           # SQLiteデータベース
│   ├── api/                          # 管理用REST API
│   ├── schemas/                      # Pydanticスキーマ
│   └── utils/                        # ユーティリティ
├── cli/                              # CLIツール (Typer)
├── deployment/                       # Docker/docker-compose
├── data/                             # 静的データ (IOCリスト, LLMプロンプト)
│   └── llm_prompts/                  # LLMプロンプトテンプレート
├── docs/                             # 設計ドキュメント
├── tests/                            # テスト
│   └── test_scanners/
│       └── test_llm/                 # LLM Judge テスト
└── debug/                            # デバッグ用 (gitignore対象)
```

## 技術スタック

| 用途 | 技術 |
|---|---|
| Webフレームワーク | FastAPI |
| HTTPクライアント | httpx |
| CLI | Typer + Rich |
| データベース | SQLite + SQLAlchemy |
| LLM (ローカル) | Ollama (OpenAI互換API) |
| LLM (クラウド) | Claude API (anthropic SDK), GPT API (openai SDK) |
| バリデーション | Pydantic v2 |
| ロギング | loguru |
| パッケージ管理 | uv |
| リンター/フォーマッター | ruff |
| テスト | pytest + pytest-asyncio |

## ネットワーク構成

```
ローカル開発環境:
  Guard Proxy:
    npm proxy:       localhost:4873
    PyPI proxy:      localhost:4874
    RubyGems proxy:  localhost:4875
    Admin API:       localhost:8100
  Ollama:            localhost:11434 (LLM推論)

チームサーバー:
  Guard Proxy:
    npm proxy:       guard.internal.example.com:4873
    PyPI proxy:      guard.internal.example.com:4874
    RubyGems proxy:  guard.internal.example.com:4875
    Admin API:       guard.internal.example.com:8100
  Ollama:        同一サーバー or 別ホスト（GPU搭載マシン）
```
