# Guard Proxy - 実装計画書

## フェーズ概要

| フェーズ | 内容 | 主要成果物 | 状態 |
|---|---|---|---|
| Phase 1 | MVP: クールダウン + 静的解析 (npmのみ) | 動作するnpmプロキシ | ✅ 完了 |
| Phase 2 | キャッシュ + CLI + Admin API | 開発者向けUX | ✅ 完了 |
| Phase 3 | LLM Judge: マルチプロバイダー対応 | ローカル+クラウドLLM判定 | ✅ 完了 |
| Phase 4 | PyPI + RubyGems対応 | pip install / gem install保護 | ✅ 完了 |
| Phase 5 | 運用強化 | IOC, 通知, メトリクス, CI/CD | ✅ 完了 |
| Phase 5.5 | Smart Two-Tier Scanning | LLM遅延解消, バックグラウンドスキャン | ✅ 完了 |
| Phase 6 | マルチレジストリ & Cargo | シングルポートルーティング, Cargo対応 | ✅ 完了 |
| Phase 7 | ライセンス & YARA & 到達可能性 | ライセンスコンプライアンス, YARAマーケットプレイス, 到達可能性分析 | ✅ 完了 |
| Phase 8 | 公開ベンチマーク検証 | DataDog, OSSF, OSPTrack, GuardDogカバレッジ | ✅ 完了 |

---

## Phase 1: MVP（クールダウン + 静的解析 / npmのみ）

### ゴール
`npm install`時にパッケージの安全性を検証し、危険なパッケージをブロックできる最小限のプロキシを構築する。

### タスク

#### 1-1. プロジェクト初期化
- [ ] `pyproject.toml` 作成（依存関係定義、ruff設定、pytest設定）
- [ ] `.env.example` 作成
- [ ] `.gitignore` 作成
- [ ] `.pre-commit-config.yaml` 作成
- [ ] `Taskfile.yml` 作成（lint, test, dev等のタスク定義）
- [ ] `.python-version` 作成（3.12）
- [ ] uv環境構築 (`uv sync`)

#### 1-2. アプリケーション基盤 (`app/core/`)
- [ ] `config.py` — pydantic-settingsによる設定管理
- [ ] `logging.py` — loguru設定
- [ ] `version.py` — バージョン定義
- [ ] `exceptions.py` — カスタム例外（PackageBlockedError, ScanTimeoutError等）
- [ ] `exception_handlers.py` — FastAPI例外ハンドラ

#### 1-3. スキーマ定義 (`app/schemas/`)
- [ ] `package.py` — PackageInfo, PackageMetadata
- [ ] `scan.py` — ScanRequest, ScanResult
- [ ] `decision.py` — DecisionResult (allow/deny/quarantine)

#### 1-4. レジストリクライアント (`app/registry/`)
- [ ] `npm_client.py` — npm registry APIからメタデータ取得
  - `GET https://registry.npmjs.org/<package>` → 全バージョンのメタデータ
  - `GET https://registry.npmjs.org/<package>/<version>` → 特定バージョン
  - 公開日、依存関係リスト、dist情報（tarball URL, shasum）の抽出

#### 1-5. スキャナ実装 (`app/scanners/`)
- [ ] `base.py` — ScannerProtocol定義
- [ ] `cooldown.py` — クールダウンゲート
  - 公開日から経過日数を計算
  - COOLDOWN_DAYS未満ならfail/warn
  - cooldown済みの代替バージョンを提案する機能
- [ ] `static_analysis.py` — 静的解析スキャナ
  - package.jsonからinstallスクリプトを抽出
  - スクリプト本体のパターンマッチング
- [ ] `patterns/npm_patterns.py` — npm向け検出パターン定義
  - クレデンシャルアクセスパターン
  - 外部通信パターン
  - 難読化パターン
  - 既知の悪意あるパターン（plain-crypto-js等）

#### 1-6. 判定エンジン (`app/decision/`)
- [ ] `models.py` — 判定結果モデル
- [ ] `engine.py` — 重み付きスコアリングロジック
  - 各スキャナのScanResultを受け取り統合
  - 閾値ベースでallow/quarantine/deny判定

#### 1-7. ユーティリティ (`app/utils/`)
- [ ] `tarball.py` — tarball展開、installスクリプト系ファイルの抽出
- [ ] `hash.py` — パッケージハッシュ計算（キャッシュキー用）

#### 1-8. npmプロキシ (`app/proxy/`)
- [ ] `base.py` — 抽象プロキシ基底クラス
- [ ] `npm.py` — npmプロキシ実装
  - メタデータリクエストの中継
  - tarballダウンロードリクエストのインターセプト
  - tarballを一時ディレクトリに展開 → スキャン → 中継/ブロック
- [ ] `middleware.py` — リクエストロギング

#### 1-9. アプリケーション起動 (`app/main.py`)
- [ ] FastAPIアプリ初期化
- [ ] プロキシルーティング設定
- [ ] lifespan（startup/shutdown）
- [ ] 例外ハンドラ登録

#### 1-10. テスト
- [ ] `tests/test_scanners/test_cooldown.py`
- [ ] `tests/test_scanners/test_static_analysis.py`
- [ ] `tests/test_decision/test_engine.py`
- [ ] `tests/test_registry/test_npm_client.py`
- [ ] `tests/test_proxy/test_npm.py`
- [ ] `tests/conftest.py` — 共通フィクスチャ

#### 1-11. Docker
- [ ] `deployment/Dockerfile`
- [ ] `deployment/docker-compose.yml`

### 完了条件
- `.npmrc`でregistry設定を変更し、`npm install <package>`が正常に動作する
- cooldown期間内のパッケージが適切にブロック/警告される
- 悪意あるpostinstallパターン（base64+eval等）が検出される
- 正当なパッケージ（node-gyp等）が誤検知されない

---

## Phase 2: キャッシュ + CLI

### ゴール
スキャン結果をキャッシュして高速化し、開発者向けCLIを提供する。

### タスク

#### 2-1. データベース (`app/db/`)
- [ ] `session.py` — SQLiteセッション管理（WALモード有効化）
- [ ] `models/scan_result.py` — スキャン結果キャッシュモデル
- [ ] `models/audit_log.py` — 監査ログモデル
- [ ] マイグレーションスクリプト

#### 2-2. キャッシュ統合
- [ ] スキャンパイプライン開始前にキャッシュ確認
- [ ] スキャン完了後にキャッシュ保存
- [ ] キャッシュキー: `{registry}:{package_name}:{version}:{content_hash}`
- [ ] TTL管理（デフォルト7日）

#### 2-3. CLI (`cli/`)
- [ ] `main.py` — Typerエントリポイント
- [ ] `commands/start.py` — `guard-proxy start`
- [ ] `commands/scan.py` — `guard-proxy scan <package>`
- [ ] `commands/config.py` — `guard-proxy config show/init`
- [ ] `commands/cache.py` — `guard-proxy cache list/clear/stats`
- [ ] `output.py` — Rich による整形出力

#### 2-4. 管理API (`app/api/`)
- [ ] `routers/health.py` — ヘルスチェック
- [ ] `routers/scan.py` — 手動スキャンAPI
- [ ] `routers/cache.py` — キャッシュ管理API

#### 2-5. テスト追加
- [ ] `tests/test_cli/test_commands.py`
- [ ] キャッシュヒット/ミスのテスト

### 完了条件
- 同一パッケージの再スキャンがキャッシュにより高速化される
- `guard-proxy` CLIコマンドが動作する
- `guard-proxy scan axios@1.13.6` で手動スキャン結果が確認できる

---

## Phase 3: LLM Judge — マルチプロバイダー対応

### ゴール
ローカルLLM（Ollama）とクラウドLLM（Claude API / GPT API）を組み合わせた柔軟なLLM判定エンジンを構築する。コストをかけるか時間をかけるかをユーザーが選択できるようにする。

### タスク

#### 3-1. LLMプロバイダー抽象化 (`app/scanners/llm/provider.py`)
- [ ] `LLMProvider` Protocol定義
  ```python
  class LLMProvider(Protocol):
      async def judge(self, prompt: str, schema: dict) -> JudgeResult: ...
      async def is_available(self) -> bool: ...
      @property
      def provider_name(self) -> str: ...
  ```
- [ ] `JudgeResult` モデル定義（verdict, reasons, confidence, suspicious_lines, provider_name, latency_ms, token_usage）

#### 3-2. Ollamaプロバイダー (`app/scanners/llm/ollama_provider.py`)
- [ ] httpx経由でOllama OpenAI互換API (`/v1/chat/completions`) に接続
- [ ] `format: json_schema` パラメータによる構造化出力の強制
- [ ] Ollama起動チェック（`GET /api/tags`）による `is_available()` 実装
- [ ] モデル存在確認（指定モデルがpull済みか）
- [ ] タイムアウト処理（ローカル推論は60秒デフォルト）

#### 3-3. Anthropicプロバイダー (`app/scanners/llm/anthropic_provider.py`)
- [ ] anthropic SDKによるClaude API連携
- [ ] `tool_use` による構造化出力
- [ ] API鍵チェックによる `is_available()` 実装
- [ ] タイムアウト処理（30秒デフォルト）
- [ ] リトライロジック（429/5xx対応）

#### 3-4. OpenAIプロバイダー (`app/scanners/llm/openai_provider.py`)
- [ ] openai SDKによるGPT API連携
- [ ] `response_format: json_schema` による構造化出力
- [ ] API鍵チェックによる `is_available()` 実装
- [ ] タイムアウト/リトライ処理

#### 3-5. デオブフスケーター (`app/scanners/llm/deobfuscator.py`)
- [ ] Base64エンコード文字列の検出とデコード
- [ ] hex/unicode エスケープの展開
- [ ] `eval()`/`exec()` 引数の抽出
- [ ] 難読化スコアの算出（0.0〜1.0）
  - Base64/hexの割合、変数名のエントロピー、コードの可読性
  - 高スコア（≥0.7）の場合はローカルLLMをスキップしてクラウドに直接送信

#### 3-6. プロンプトビルダー (`app/scanners/llm/prompt_builder.py`)
- [ ] プロバイダー共通のプロンプト構築ロジック
- [ ] `data/llm_prompts/` テンプレートの読み込みと変数展開
- [ ] デオブフスケート結果の埋め込み
- [ ] コンテキスト長制限の適用（プロバイダー別）

#### 3-7. LLM Judgeルーター (`app/scanners/llm/judge.py`)
- [ ] 4つの実行戦略の実装:
  - `local_first`: ローカル → confidence低ならクラウドにエスカレーション
  - `cloud_only`: クラウドLLMのみ
  - `local_only`: ローカルLLMのみ
  - `consensus`: ローカル+クラウド両方実行、合意判定
- [ ] エスカレーション閾値（`LOCAL_CONFIDENCE_THRESHOLD`）の適用
- [ ] フォールバックチェーン: Ollama → Anthropic → OpenAI → degraded mode
- [ ] 難読化スコアによるクラウド直接送信判定
- [ ] `ScannerProtocol`の実装（既存パイプラインへの統合）

#### 3-8. コスト制御・モニタリング
- [ ] 日次クラウドAPI呼び出し上限（`CLOUD_DAILY_LIMIT`）
- [ ] プロバイダー別トークン使用量のロギング
- [ ] `app/db/models/llm_usage.py` — 使用量トラッキングモデル
- [ ] スキャン対象ファイルサイズ上限（デフォルト512KB）

#### 3-9. 判定エンジン更新 (`app/decision/`)
- [ ] LLM Judgeスキャナの重み設定追加
- [ ] 3スキャナの結果統合ロジック更新
- [ ] LLM Judgeの `provider_name` を判定結果メタデータに記録

#### 3-10. CLI拡張 (`cli/commands/llm.py`)
- [ ] `guard-proxy llm status` — 各プロバイダーの接続状況・モデル確認
- [ ] `guard-proxy llm test` — テストプロンプトで動作確認
- [ ] `guard-proxy llm usage` — 日次/月次のAPI使用量表示

#### 3-11. テスト
- [ ] `tests/test_scanners/test_llm/test_ollama_provider.py`（モックサーバー使用）
- [ ] `tests/test_scanners/test_llm/test_anthropic_provider.py`（モックAPI使用）
- [ ] `tests/test_scanners/test_llm/test_openai_provider.py`（モックAPI使用）
- [ ] `tests/test_scanners/test_llm/test_judge.py`（戦略別テスト）
- [ ] `tests/test_scanners/test_llm/test_deobfuscator.py`
- [ ] フォールバックチェーンの動作テスト
- [ ] エスカレーション閾値の動作テスト
- [ ] consensus戦略の合意ロジックテスト

### 完了条件
- `LLM_STRATEGY=local_only` でOllama（Qwen3.5-9B）のみで判定が完了する
- `LLM_STRATEGY=local_first` でconfidence低時にクラウドへエスカレーションされる
- `LLM_STRATEGY=cloud_only` でClaude/GPTのみで判定が完了する
- `LLM_STRATEGY=consensus` でローカル+クラウドの合意判定が動作する
- Ollama未起動時にクラウドへのフォールバックが正常に動作する
- 全プロバイダー障害時にdegraded modeで動作する
- node-gypの正当なビルドスクリプトが誤検知されない
- axios@1.14.1相当の悪意あるpostinstallが正しく検出される
- `guard-proxy llm status` で全プロバイダーの状態が確認できる
- 難読化されたコードがデオブフスケート後にLLMに渡される

---

## Phase 4: PyPI + RubyGems対応

### ゴール
`pip install` / `gem install` / `bundle install` でも同様の保護を提供する。

### PyPI タスク（✅ 完了）

- [x] `app/registry/pypi_client.py` — PyPI JSON API + Simple API
- [x] `app/proxy/pypi.py` — PEP 503 Simple API互換プロキシ + whl/sdistインターセプト
- [x] `app/scanners/patterns/pypi_patterns.py` — setup.py, .pth, cmdclass, cloud metadata検出
- [x] `app/scanners/static_analysis_pypi.py` — PyPI専用静的解析スキャナ
- [x] `data/llm_prompts/pypi_analysis.txt` — LLM Judgeプロンプト

### RubyGems タスク（✅ 完了）

- [x] `app/registry/rubygems_client.py` — RubyGems JSON API + Compact Index
- [x] `app/proxy/rubygems.py` — Compact Indexパススルー + .gemインターセプト
- [x] `app/scanners/patterns/rubygems_patterns.py` — extconf.rb, ENV, eval, system, backtick検出
- [x] `app/scanners/static_analysis_rubygems.py` — RubyGems専用静的解析（mkmf誤検知除外）
- [x] `data/llm_prompts/rubygems_analysis.txt` — LLM Judgeプロンプト
- [x] `app/utils/tarball.py` — .gem展開（outer tar → metadata.gz + data.tar.gz）
- [x] `app/utils/install_hooks.py` — gemspec extensions + rubygems_plugin.rb検出

### 完了条件
- [x] `pip install <package>` がプロキシ経由で正常動作する
- [x] `gem install <gem> --source http://proxy:4875` がプロキシ経由で正常動作する
- [x] `bundle config mirror` で全トラフィックがプロキシ経由になる
- [x] .pthファイル、extconf.rbの不審なコードが検出される

---

## Phase 5: 運用強化

### ゴール
本番利用に耐える品質・運用性を確保する。

### タスク

#### 5-1. IOCデータベース
- [ ] `app/db/models/ioc.py` — IOCエントリモデル
- [ ] 既知の悪意あるパッケージリストの初期データ
- [ ] IOCリストの定期更新メカニズム（GitHub等からfetch）

#### 5-2. 監査・可観測性
- [ ] 監査ログの充実（全リクエスト、判定理由の記録）
- [ ] Prometheusメトリクス（リクエスト数、ブロック数、スキャン時間、LLMプロバイダー別使用量）
- [ ] ダッシュボードUI（オプション）

#### 5-3. 通知
- [ ] Slack webhook連携（ブロック/quarantine時に通知）
- [ ] GitHub Issue自動作成（オプション）

#### 5-4. DevContainer対応
- [ ] devcontainer-feature の作成
- [ ] コンテナ起動時のプロキシ自動設定
- [ ] Ollama sidecarコンテナの自動起動設定

#### 5-5. CI/CD
- [ ] GitHub Actions ワークフロー（lint, test, build, publish）
- [ ] PyPIへの公開準備

#### 5-6. ドキュメント
- [ ] README.md（英語）
- [ ] 利用ガイド
- [ ] コントリビューションガイド
- [ ] LLMプロバイダー設定ガイド

### 完了条件
- OSSとして公開可能な品質
- `pip install guard-proxy` でインストール可能
- DevContainerとして統合可能
- Ollama sidecarを含むdocker-composeで一発起動可能

---

## Phase 6: マルチレジストリ & Cargo（v2.1.0-v2.2.0）— ✅ 完了

### ゴール
すべてのレジストリプロキシをパスベースルーティングでシングルポートに統合し、Cargo（Rust）エコシステムのサポートを追加する。

### タスク

#### 6-1. シングルポートルーティング
- [x] パスベースの統一ルーティング（`/npm/`, `/pypi/`, `/gems/`, `/go/`, `/cargo/`）
- [x] リクエストパスからの自動レジストリ検出
- [x] 後方互換性のあるスタンドアロンポートモード

#### 6-2. Cargoレジストリ対応
- [x] `app/registry/cargo_client.py` — crates.io APIクライアント
- [x] `app/proxy/cargo.py` — Cargoレジストリプロキシ
- [x] `app/scanners/patterns/cargo_patterns.py` — Cargo固有の20検出パターン
- [x] `build.rs`重大度ブースト（ネイティブビルドスクリプトを高リスクとして扱う）

### 完了条件
- [x] 5つのレジストリすべてがパスプレフィックス付きのシングルポートでアクセス可能
- [x] `cargo install <crate>` がプロキシ経由で正常動作
- [x] 不審なパターンを持つ`build.rs`ファイルがブースト重大度で検出される

---

## Phase 7: ライセンス & YARA & 到達可能性（v2.3.0-v2.5.0）— ✅ 完了

### ゴール
ライセンスコンプライアンススキャン、コミュニティYARAルールサポート、偽陽性削減のための到達可能性分析、回避技術に対する検出強化を追加する。

### タスク

#### 7-1. ライセンスコンプライアンススキャナ（v2.3.0）
- [x] SPDXエクスプレッション解析とエイリアス正規化
- [x] 設定可能な許可/拒否リストポリシー
- [x] コピーレフト検出を個別の設定可能アクションとして提供
- [x] LLMなしで動作

#### 7-2. YARAルールマーケットプレイス（v2.4.0）
- [x] URL + SHA256変更検出によるコミュニティルールソース
- [x] CLI管理（`guard-proxy yara add/remove/update/list`）
- [x] 起動時自動更新（オプトイン）
- [x] LLMなしで動作

#### 7-3. 到達可能性分析（v2.5.0）
- [x] ファイル内ASTベースのコールグラフ分析
- [x] PythonおよびJavaScriptサポート
- [x] 到達不可能な危険コードを「pass」としてマークし偽陽性を削減
- [x] LLMなしで動作

#### 7-4. 検出強化
- [x] クリティカルパターンは安全なインジケータがあってもダウングレードしない
- [x] 高重大度の単一マッチ = fail判定
- [x] 正規表現ウィンドウ縮小によるReDoS緩和
- [x] 全スキャナにわたる回避耐性の改善

### 完了条件
- [x] ライセンスポリシー違反が設定に基づいて検出・報告される
- [x] コミュニティYARAルールの取得、検証、スキャン適用が可能
- [x] 到達可能性分析により偽陽性率が低減
- [x] 既知の回避技術が検出強化によりブロックされる

---

## Phase 8: 公開ベンチマーク検証 — ✅ 完了

### ゴール
公開されている悪意あるパッケージデータセットに対してGuard Proxyの検出能力を検証し、カバレッジメトリクスを確立する。

### タスク

#### 8-1. データセット検証
- [x] DataDog悪意あるパッケージデータセット: 11,291/11,291（100%）IOCカバレッジ
- [x] osv.dev API経由のOSSFクロスリファレンス
- [x] OSPTrack Zenodoデータセット検証
- [x] GuardDogルールカバレッジ: 全エコシステム100%

#### 8-2. テストスイート
- [x] 730以上のテスト通過

### 完了条件
- [x] DataDogデータセットで100% IOCカバレッジ
- [x] 全エコシステムで100% GuardDogルールカバレッジ
- [x] OSPTrackおよびOSSFデータセットの検証完了
- [x] 730以上のテスト通過
