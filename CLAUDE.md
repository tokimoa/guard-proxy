# Guard Proxy - Claude Code ガイドライン

## プロジェクト概要
npm/PyPI/RubyGemsのサプライチェーン攻撃から開発者を保護するセキュリティプロキシ。
パッケージのinstall時に透過的にスキャンし、悪意あるパッケージをブロックする。

## 技術スタック
- Python 3.12 / FastAPI / httpx / SQLAlchemy / Typer
- LLM Judge: Ollama (ローカル) / Claude API / GPT API（マルチプロバイダー）
- SQLite for cache, audit log, and IOC database
- uv for package management
- ruff for linting/formatting

## 開発コマンド
```bash
uv sync                    # 依存関係インストール
uv run pytest              # テスト実行
uv run ruff check .        # リント
uv run ruff format .       # フォーマット
uv run guard-proxy start   # プロキシ起動
```

## 規約
- docs/のメインドキュメントは英語で記述（*_ja.md で日本語版を併記）
- README.mdとコード内コメントは英語
- Pydantic v2 を使用（v1構文は使わない）
- 非同期処理はasync/awaitを使用
- テストはpytest + pytest-asyncio
