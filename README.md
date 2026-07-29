# api-cli

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

既存REST APIを、認証情報をAIへ渡さず、明示的に許可した操作だけに限定して公開する
Local-first Agent Capability Gatewayです。CLIの汎用REST呼び出しはデバッグ用途として維持し、
MCPには`ActionDefinition`から生成したToolだけを公開します。

---

## 📖 ドキュメント

- [APIサーバー連携ガイド](docs/server-integration-guide.md) — api-cli と連携するためにサーバー側で必要な実装
- [Capability Broker実装計画](docs/capability-broker-implementation-plan.md) — ActionDefinition中心の安全なMCP Gatewayへの段階移行計画

## ✨ 特徴

| 機能 | 説明 |
|------|------|
| **マルチプロバイダー** | 複数のAPIサービスを個別に登録・管理 |
| **OAuth2 PKCE** | ブラウザ経由の安全なOAuthログイン |
| **API Key** | 対話入力によるセキュアなキー登録（シェル履歴・プロセス一覧に残らない） |
| **暗号化ストレージ** | トークン・秘密情報をAES-256-GCMで暗号化しローカル保存 |
| **Action Registry** | JSON Schema付きの限定操作をYAML/JSONで定義 |
| **OpenAPI import** | `operationId`を無効状態のAction下書きとして取り込み |
| **MCPサーバー** | `rmcp`によるstdio / OAuth保護Streamable HTTP |
| **承認・監査** | 全引数に結び付いた期限付き・一回限りの承認と秘密を残さない監査ログ |
| **単一バイナリ** | Rust製。外部ランタイム不要 |

## 📦 インストール

### 前提条件

- [Rust](https://www.rust-lang.org/tools/install) 1.88 以上

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

# Bearerではなく専用ヘッダーを使うAPI Key
api-cli provider add \
  --id header-service \
  --base-url https://api.example.com \
  --auth-type api-key \
  --api-key-header x-api-key

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

# OAuth PKCE — 表示されたURLをブラウザで開きます
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

### ActionDefinition

設定ディレクトリの`actions.d`へ、レビュー済みのActionを配置します。MCPクライアントは
`provider`、任意のmethod、任意のpathを指定できません。

```yaml
api_version: apicli.dev/v1alpha1
kind: Action
metadata:
  name: customer.get
  version: 1
  description: 顧客情報を取得する
  enabled: true
spec:
  input_schema:
    type: object
    additionalProperties: false
    properties:
      customer_id: { type: string, minLength: 1 }
    required: [customer_id]
  output_schema:
    type: object
  executor:
    kind: openapi
    provider: crm
    operation_id: getCustomer
    method: GET
    path: /customers/{customer_id}
    parameters:
      customer_id: path
  risk: read
  approval: never
  broker_scopes: [customer:read]
  upstream_scopes: [crm.customer.read]
  constraints:
    timeout_ms: 10000
    max_response_bytes: 1048576
    response_mask: [/email, /phone]
```

```bash
api-cli action validate ./customer.get.yaml
api-cli action list
api-cli action describe customer.get
api-cli action run customer.get --input '{"customer_id":"c-1"}'

# OpenAPI 3のoperationIdから、enabled: falseのレビュー用下書きを生成
api-cli openapi validate ./openapi.yaml
api-cli openapi import ./openapi.yaml --provider crm --output-dir ./actions.d
```

書き込みActionは`prepare → approve → run`で実行します。チケットは主体、tenant、Action、
provider、正規化済み全引数、policy version、期限に結び付き、一回だけ消費できます。

```bash
TICKET=$(api-cli action prepare customer.update \
  --input '{"customer_id":"c-1","status":"suspended"}')
api-cli action approve "$TICKET"
api-cli action run customer.update \
  --input '{"customer_id":"c-1","status":"suspended"}' \
  --approval-ticket "$TICKET"
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

公開Toolは`enabled: true`のActionDefinitionから動的に生成されます。汎用`api_call`と
provider一覧は公開されません。書き込みではMCP 2026-07-28のMRTR elicitationで確認します。

Remote MCPはOAuth 2.0 token introspectionで`active`、`aud`、`sub`、`tenant_id`、`scope`
を検証します。introspection用client secretは引数ではなく環境変数から渡します。

```bash
export API_CLI_MCP_INTROSPECTION_SECRET='...'
api-cli mcp serve-http \
  --listen 127.0.0.1:3000 \
  --introspection-url https://id.example.com/oauth/introspect \
  --audience https://broker.example.com/mcp \
  --client-id api-cli-broker \
  --allowed-host localhost:3000 \
  --allowed-origin https://app.example.com \
  --max-sessions 1024 \
  --max-request-bytes 1048576
```

Remoteでは検証済みscopeによりTool一覧を絞り込みます。server-side承認サービスを別途
接続するまではread-only Actionだけを公開します。さらに上流credentialは
`(tenant_id, principal_id, provider_id)`が一致するものだけを利用します。Remote principal用の
credential接続作成UIは未実装のため、現段階のRemote transportは統合・認証検証用途です。
各MCP sessionは作成時の`tenant_id`、`sub`、client IDへ固定され、別identityからのsession ID
再利用は拒否されます。同時保持session数にも上限があります。
HTTP request bodyも既定1 MiB（設定可能、最大16 MiB）に制限します。
MCP listener自体はHTTPのため通常はloopbackへbindし、同一ホストのTLS reverse proxyを前段に
置きます。non-loopbackへ直接bindする場合は、危険性を明示する`--allow-insecure-http`が必要です。

## 🏗️ アーキテクチャ

```
┌─────────────────────┐
│   CLI / MCP Layer   │  ← ユーザー or LLM とのインターフェース
├─────────────────────┤
│   Action Registry    │  ← allowlist・入出力Schema・risk・constraints
├─────────────────────┤
│ Policy / Approval   │  ← scope・一回限りticket・監査
├─────────────────────┤
│ Credential / HTTP   │  ← OAuth/API Key・SQLite・暗号化・egress制限
└─────────────────────┘
```

## 🔒 セキュリティ

- 秘密情報（トークン・APIキー）は**平文で保存されません**。AES-256-GCM で暗号化されます。
- 暗号鍵 `vault.key`（32バイト）は初回起動時に自動生成され、パーミッション `0600` で保護されます。
- API キーは対話入力で取得するため、シェル履歴やプロセス引数に残りません。
- MCPにはレビュー済みActionだけを公開し、任意method/pathのREST呼び出しは公開しません。
- HTTP応答はstreaming中もサイズ上限を検査し、timeout、redirect、originを制限します。
- private/loopback/link-local宛てはproviderの明示設定がない限り拒否します。
- 同じprovider IDの上書きは拒否し、provider削除時にはsessionと参照可能なVault secretを失効・削除します。
- Vault DBと鍵が同じOSユーザー領域にあるため、同じOSユーザーが侵害された場合の防御には
  なりません。OS Keychain等による鍵のラップは今後のハードニング対象です。

## 📁 データ保存先

```
<OSのapi-cli設定ディレクトリ>/
├── metadata.db   # プロバイダー設定・セッション情報（SQLite）
├── vault.db      # 暗号化された秘密情報（SQLite）
├── vault.key     # 暗号鍵（0600）
└── actions.d/    # ActionDefinition（YAML / JSON）
```

## 🖥️ 対応OS

- macOS
- Linux
- WSL (Windows Subsystem for Linux)

## 🤝 コントリビューション

Issue や Pull Request を歓迎します。バグ報告や機能提案は [Issues](https://github.com/<your-username>/api-cli/issues) からお願いします。

## 📄 ライセンス

[MIT License](LICENSE)
