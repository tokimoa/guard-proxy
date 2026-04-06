# LLM セットアップガイド

English version: [LLM_SETUP_GUIDE.md](LLM_SETUP_GUIDE.md)

Guard ProxyはLLMなしでも動作しますが、LLMを有効にすると**難読化された攻撃コード**や**未知の攻撃パターン**の検出精度が向上します。

---

## LLMあり/なしの違い

| | LLMなし | LLMあり |
|---|---|---|
| 既知の攻撃パターン（base64+eval, C2通信等） | ✅ 検出可能 | ✅ 検出可能 |
| IOC（既知の悪意あるパッケージ） | ✅ 即ブロック | ✅ 即ブロック |
| タイポスクワット | ✅ 検出可能 | ✅ 検出可能 |
| 変数間接参照（`const e = eval; e(code)`） | ✅ AST解析で検出 | ✅ AST + LLMで検出 |
| **複雑な難読化**（XOR + 多段エンコーディング） | ⚠️ 一部検出 | ✅ LLMが文脈で判定 |
| **未知の攻撃パターン** | ❌ 検出困難 | ✅ LLMが意図を推論 |

**結論**: LLMなしでも**90%以上の攻撃を検出**できます。LLMは「人間の判断が必要なグレーゾーン」をカバーします。

---

## 3つの選択肢

### Option A: LLMなし（最も簡単）

追加設定不要。デフォルトで`LLM_ENABLED=false`です。

```bash
uv sync
guard-proxy start
```

これだけで12種のfast-tierスキャナ（IOC、Advisory、Cooldown、Metadata（タイポスクワット）、Maintainer、Static Analysis、Heuristics、AST、YARA、Reachability、License、Dependency）が有効になります。

> **注**: ライセンスコンプライアンススキャン、到達可能性分析、YARAルールマーケットプレイスはすべてLLMなしで動作します。LLMコストゼロで高い検出カバレッジを提供します。

### Option B: ローカルLLM（Ollama）— 推奨

**無料。データが外部に送信されない。**

#### Ollamaインストール

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
[https://ollama.com/download](https://ollama.com/download) からダウンロード

#### モデルダウンロード

```bash
ollama pull qwen3.5:latest    # 推奨（5GB、8GB RAM必要）
```

メモリが足りない場合:
```bash
ollama pull qwen3:4b          # 軽量版（3GB、4GB RAM）
```

#### Guard Proxy設定

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=local_only
OLLAMA_MODEL=qwen3.5:latest
EOF

guard-proxy start
```

### Option C: クラウドLLM（Claude / GPT）

```bash
cat > .env << 'EOF'
LLM_ENABLED=true
LLM_STRATEGY=cloud_only
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxx
EOF
```

---

## 4つの戦略（LLM_STRATEGY）

| 戦略 | 動作 | コスト/月 |
|---|---|---|
| `local_only` | Ollamaだけ使用 | **$0** |
| `local_first` | Ollama → 確信度低ならクラウド | **$0.5〜$2** |
| `cloud_only` | Claude/GPTだけ使用 | **$5〜$15** |
| `consensus` | ローカル+クラウド両方で合意判定 | **$5〜$15** |

---

## モデルの選び方（2026年4月時点）

### 推奨モデル

| モデル | パラメータ | サイズ | RAM | コード分析精度 | JSON安定性 |
|---|---|---|---|---|---|
| **`qwen3.5:latest`** | 8B | 5GB | 8GB | ★★★★★ | ◎ 安定 |
| **`gemma4:26b`** | 26B (MoE, 4B active) | 18GB | 18GB | ★★★★★ | ◎ 安定 |
| **`qwen3-coder:30b`** | 30B (MoE, 3.3B active) | 19GB | 20GB | ★★★★★+ | ◎ 安定 |
| `mistral-small3.2:24b` | 24B | 15GB | 18GB | ★★★★☆ | ◎ 安定 |
| `phi4:14b` | 14B | 9GB | 10GB | ★★★★☆ | ○ 良好 |
| `gemma4:e4b` | 4B | 10GB | 8GB | ★★★★☆ | ○ 良好 |
| `qwen3:4b` | 4B | 3GB | 4GB | ★★★☆☆ | ○ 良好 |

### どれを選ぶ？

- **迷ったら** → `qwen3.5:latest`（デフォルト推奨）
- **32GB RAM** → `gemma4:26b` or `qwen3-coder:30b`（MoE高精度）
- **8GB RAM** → `qwen3.5:latest`
- **4GB RAM** → `qwen3:4b`

> MoEモデルはパラメータ数が大きくても推論が高速。DeepSeek R1系はJSON不安定のため非推奨。

---

## トラブルシューティング

**「Ollama not running」:**
```bash
curl http://localhost:11434/api/tags   # 応答がなければ↓
ollama serve                            # Ollamaを起動
```

**「Model not found」:**
```bash
ollama list                             # モデル一覧確認
ollama pull qwen3.5:latest             # なければダウンロード
```
