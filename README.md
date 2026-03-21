# api-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

複数の外部APIに対して**安全に認証・通信**を行うためのCLIツール / MCPサーバーです。

---

## 📖 ドキュメント

- [APIサーバー連携ガイド](docs/server-integration-guide.md) — api-cli と連携するためにサーバー側で必要な実装

## ✨ 特徴

| 機能 | 説明 |
|------|------|
| **マルチプロバイダー** | 複数のAPIサービスを個別に登録・管理 |
| **OAuth2 PKCE** | ブラウザ経由の安全なOAuthログイン |
| **API Key** | 対話入力によるセキュアなキー登録（シェル履歴・プロセス一覧に残らない） |
| **暗号化ストレージ** | トークン・秘密情報をAES-256-GCMで暗号化しローカル保存 |
| **MCPサーバー** | Claude等のLLMから安全にAPIを呼び出すMCPサーバーを内蔵 |
| **承認フロー** | LLM経由の実行に対するユーザー承認メカニズム |
| **単一バイナリ** | Rust製。外部ランタイム不要 |

## 📦 インストール

### 前提条件

- [Rust](https://www.rust-lang.org/tools/install) 1.75 以上

### ソースからビルド

```bash
git clone https://github.com/<your-username>/api-cli.git
cd api-cli
cargo install --path .
```

## 🚀 使い方

### プロバイダーの登録

```bash
# API Key 認証
api-cli provider add \
  --id my-service \
  --base-url https://api.example.com \
  --auth-type api-key

# OAuth PKCE 認証
api-cli provider add \
  --id github \
  --base-url https://api.github.com \
  --auth-type oauth-pkce \
  --client-id <your-client-id> \
  --auth-url https://github.com/login/oauth/authorize \
  --token-url https://github.com/login/oauth/access_token \
  --scopes "repo,user"
```

### ログイン

```bash
# API Key — 実行時に対話的に入力を求められます
api-cli auth login my-service

# OAuth PKCE — ブラウザが自動的に開きます
api-cli auth login github
```

### API 呼び出し

```bash
api-cli api call github GET /user
api-cli api call my-service POST /v1/items --body '{"name":"example"}'
```

### プロバイダー管理

```bash
api-cli provider list          # 登録済みプロバイダー一覧
api-cli provider remove <id>   # プロバイダー削除
api-cli auth status <id>       # 認証状態の確認
```

### MCP サーバー

LLM クライアント（Claude Desktop 等）から API を呼び出すための MCP サーバーを起動します。

```bash
api-cli mcp serve
```

#### Claude Desktop での設定例

`claude_desktop_config.json` に以下を追加します:

```json
{
  "mcpServers": {
    "api-cli": {
      "command": "api-cli",
      "args": ["mcp", "serve"]
    }
  }
}
```

#### 公開ツール

| ツール名 | 説明 |
|----------|------|
| `list_providers` | 登録済みプロバイダー一覧を返す |
| `api_call` | 指定プロバイダーの API を実行（`provider_id`, `method`, `path`, `body`） |

## 🏗️ アーキテクチャ

```
┌─────────────────────┐
│   CLI / MCP Layer   │  ← ユーザー or LLM とのインターフェース
├─────────────────────┤
│  Application Layer  │  ← 認証フロー・API実行のオーケストレーション
├─────────────────────┤
│    Domain Layer     │  ← プロバイダー・セッション・承認ルール
├─────────────────────┤
│  Infrastructure     │  ← SQLite永続化 / AES-256-GCM暗号化 / HTTP
└─────────────────────┘
```

## 🔒 セキュリティ

- 秘密情報（トークン・APIキー）は**平文で保存されません**。AES-256-GCM で暗号化されます。
- 暗号鍵 `vault.key`（32バイト）は初回起動時に自動生成され、パーミッション `0600` で保護されます。
- API キーは対話入力で取得するため、シェル履歴やプロセス引数に残りません。
- LLM 経由の API 呼び出しにはユーザー承認が必要です。

## 📁 データ保存先

```
~/.api-cli/
├── metadata.db   # プロバイダー設定・セッション情報（SQLite）
├── vault.db      # 暗号化された秘密情報（SQLite）
├── vault.key     # 暗号鍵（0600）
└── runtime/
    └── mcp.sock  # MCPサーバーのIPCソケット
```

## 🖥️ 対応OS

- macOS
- Linux
- WSL (Windows Subsystem for Linux)

## 🤝 コントリビューション

Issue や Pull Request を歓迎します。バグ報告や機能提案は [Issues](https://github.com/<your-username>/api-cli/issues) からお願いします。

## 📄 ライセンス

[MIT License](LICENSE)
