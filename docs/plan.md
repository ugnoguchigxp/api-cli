# CLI設計書 v2（正式版）

## 1. 概要

本CLIは、複数のバックエンドAPIサーバーに対して安全に認証・通信を行うローカルツールである。
また、同一バイナリでMCPサーバーとして動作し、LLMからのAPI利用を安全に仲介する。

### 実装言語

Rustを採用する。理由：

* 単一バイナリ配布が容易
* クロスプラットフォーム対応（macOS / Linux / WSL）
* メモリ安全性・パフォーマンス
* 暗号ライブラリ（`ring`, `aes-gcm`）が充実

---

## 2. 設計ゴール

* 人間がシームレスに利用できるCLI
* MCP経由でLLMから安全にAPIを利用可能
* 複数（10〜20）のAPIサーバーを管理可能
* 認証情報をローカルに安全に保存
* ユーザー許可を伴うLLM実行モデル
* OS依存を最小化（macOS / Linux / WSL）

---

## 3. スコープ

### 対象

* OAuth PKCE認証
* API Key認証
* REST API呼び出し
* ローカル保存（暗号化DB）
* MCPサーバー
* approval（ユーザー許可）

### 非対象（初版）

以下は初版では対象外とし、将来的に優先度順に検討する。

| 優先度 | 機能 | 備考 |
|--------|------|------|
| 高 | 永続的approvalルール | 運用利便性向上。v2で対応予定 |
| 中 | Client Credentials | サーバー間通信用途。需要に応じて対応 |
| 中 | Device Flow | ブラウザなし環境向け。CI/CD対応時に併せて検討 |
| 低 | CI/CD対応 | headlessモードの設計が必要 |
| 低 | OS秘密ストア連携 | macOS Keychain, Linux Secret Serviceとの統合 |

---

## 4. システム構成

```
+--------------------+
|   CLI / MCP Layer  |
+--------------------+
| Application Layer  |
+--------------------+
| Domain Layer       |
+--------------------+
| Infrastructure     |
| (DB, Crypto, HTTP) |
+--------------------+
```

---

## 5. 実行モード

### CLIモード

```bash
mycli auth login billing
mycli api call billing GET /v1/items
```

### MCPモード

```bash
mycli mcp serve
```

MCPサーバーは標準入出力（stdio）経由でJSON-RPCメッセージを送受信する。

#### 通信プロトコル

* **トランスポート**: stdio（標準入出力）
* **プロトコル**: JSON-RPC 2.0（MCP仕様準拠）
* **接続方式**: LLMクライアント（Claude Desktop等）がサブプロセスとして起動

#### 公開ツール定義

| ツール名 | 説明 | 主要パラメータ |
|----------|------|----------------|
| `api_call` | APIリクエストを実行 | `provider_id`, `method`, `path`, `body` |
| `list_providers` | 登録済みprovider一覧を返す | なし |
| `auth_status` | 認証状態を返す | `provider_id` |

#### `runtime/mcp.sock`

* MCPサーバープロセスが作成するUnixドメインソケット
* CLIプロセスとMCPサーバー間のIPC（プロセス間通信）に使用
* プロセス終了時に自動削除される
* 用途: approval要求の中継、セッション共有

---

## 6. データ保存設計

### 6.1 ディレクトリ構成

```text
~/.api-cli/
  metadata.db
  vault.db
  vault.key
  runtime/
    mcp.sock
```

---

### 6.2 metadata.db

#### 役割

非秘密データの管理

#### 保存内容

* provider設定
* session metadata
* scope
* expiry
* active profile
* last_used_at
* settings

#### SQLite設定

* WAL: 有効
* 用途: 高速アクセス

---

### 6.3 vault.db

#### 役割

秘密データの保存

#### 保存内容

* access token
* refresh token
* api key

#### SQLite設定

* WAL: 無効
* journal_mode: DELETE

---

### 6.4 vault.key

#### 役割

暗号鍵

#### 仕様

* 32バイトランダム値（`CSPRNG`で生成）
* 権限: 0600
* DBとは別ファイル

#### ローテーション・バックアップ方針

* **ローテーション**: `mycli vault rotate-key` コマンドで手動実行。既存の暗号データを新鍵で再暗号化する
* **バックアップ**: ユーザー責任。CLIは `mycli vault export` で暗号化済みバックアップを提供
* **紛失時**: vault.dbの復号は不可能。再認証が必要

---

## 7. 暗号化仕様

### 7.1 方針

* vault.dbの内容は**アプリ層で暗号化**
* DB自体は通常のSQLite

### 7.2 アルゴリズム

* **方式**: AES-256-GCM（認証付き暗号）
* **鍵**: vault.keyの32バイト値をそのまま使用
* **Nonce**: 12バイト、暗号化ごとにCSPRNGで生成
* **認証タグ**: 16バイト（GCM標準）
* **ライブラリ**: `aes-gcm` crate

### 7.3 フロー

1. secret payload をJSON化
2. vault.key を読み込み
3. Nonceを生成（12バイト, CSPRNG）
4. AES-256-GCMで暗号化
5. cipher_text + nonce をDBへ保存

### 7.4 テーブル

```sql
CREATE TABLE secrets (
  secret_id TEXT PRIMARY KEY,
  kind TEXT,
  cipher_text BLOB,
  nonce BLOB,
  created_at TEXT,
  updated_at TEXT
);
```

---

## 8. provider設計

```rust
struct ProviderConfig {
    id: String,
    base_url: String,
    auth_type: AuthType,
    scopes: Vec<String>,
}
```

### 登録フロー

providerの登録はCLI経由の対話的操作で行う。

```bash
# 対話的に登録
mycli provider add

# 非対話的に登録（CI/スクリプト向け）
mycli provider add \
  --id billing \
  --base-url https://api.billing.example.com \
  --auth-type oauth-pkce \
  --scopes "read,write"
```

#### 管理コマンド

| コマンド | 説明 |
|----------|------|
| `mycli provider add` | provider登録 |
| `mycli provider list` | 一覧表示 |
| `mycli provider show <id>` | 詳細表示 |
| `mycli provider remove <id>` | 削除 |
| `mycli provider update <id>` | 設定変更 |

---

## 9. session設計

```rust
struct SessionRecord {
    session_id: String,
    provider_id: String,
    scopes: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    secret_id: String,
}
```

---

## 10. 認証

### 10.1 OAuth PKCE

* browser login
* localhost callback
* token取得
* vault保存

#### トークンリフレッシュ

* API呼び出し時にaccess tokenの有効期限を確認
* 期限切れ（または期限30秒前）の場合、自動的にrefresh tokenでリフレッシュ
* リフレッシュ成功時: 新しいaccess token / refresh tokenをvaultに上書き保存
* リフレッシュ失敗時（refresh token失効等）: `AUTH_EXPIRED` エラーを返し、再ログインを促す
* 同時リフレッシュの排他制御: ミューテックスで単一実行を保証

### 10.2 API Key

* CLI入力
* vault保存

---

## 11. API実行

```rust
struct ApiRequest {
    provider_id: String,
    method: HttpMethod,
    path: String,
    body: Option<Json>,
}
```

---

## 12. 出力仕様

### 成功

```json
{
  "ok": true,
  "data": {}
}
```

### エラー

```json
{
  "ok": false,
  "code": "AUTH_REQUIRED",
  "message": "..."
}
```

### エラーコード一覧

| コード | 説明 |
|--------|------|
| `AUTH_REQUIRED` | 認証が必要（未ログイン） |
| `AUTH_EXPIRED` | トークン期限切れ（リフレッシュ失敗） |
| `AUTH_FAILED` | 認証処理に失敗 |
| `PROVIDER_NOT_FOUND` | 指定されたproviderが存在しない |
| `PROVIDER_ALREADY_EXISTS` | 同名のproviderが既に登録済み |
| `API_ERROR` | APIサーバーからのエラー応答 |
| `API_TIMEOUT` | APIリクエストがタイムアウト |
| `API_UNREACHABLE` | APIサーバーに接続できない |
| `VAULT_ERROR` | vault操作（暗号化/復号）の失敗 |
| `VAULT_KEY_MISSING` | vault.keyが見つからない |
| `APPROVAL_DENIED` | ユーザーが操作を拒否 |
| `APPROVAL_TIMEOUT` | approval応答がタイムアウト |
| `INVALID_INPUT` | 不正な入力パラメータ |
| `INTERNAL_ERROR` | 内部エラー |

---

## 13. approval設計

### 13.1 目的

LLM経由の操作に対してユーザー確認を挟む

### 13.2 フロー

1. MCPから要求
2. CLIが表示
3. ユーザー許可
4. 実行

---

### 13.3 セッション内キャッシュ

```rust
struct ApprovalKey {
    provider_id: String,
    method: String,
    path: String,
}
```

#### 仕様

* 一度許可 → 同セッション内は再確認なし
* プロセス終了でリセット

---

## 14. セキュリティモデル

### 守るもの

* トークンの平文保存回避
* DB単体流出防止
* 誤ログ出力防止

### 守らないもの

* 同一ユーザー権限での侵害
* 実行中プロセスメモリ

（AWS/Azureと同等レベル）

---

## 15. OS対応

* macOS
* Linux
* WSL

---

## 16. 配布

* GitHub Releases
* Homebrew
* apt
* winget（任意）

---

## 17. 非機能要件

* 単一バイナリ
* 起動高速
* 外部依存最小
* JSON出力安定

---

## 18. ログ・デバッグ

### ログレベル

| レベル | 出力先 | 用途 |
|--------|--------|------|
| `error` | stderr | 致命的エラー |
| `warn` | stderr | 警告 |
| `info` | stderr | 通常操作ログ |
| `debug` | stderr | 詳細デバッグ（`--verbose` 指定時） |
| `trace` | stderr | 最詳細（`--trace` 指定時） |

### セキュリティルール

* トークン、API Key、パスワード等の秘密情報は**一切ログ出力しない**
* HTTPリクエスト/レスポンスのログには `Authorization` ヘッダーをマスクする
* debugレベル以上でも秘密情報は `[REDACTED]` で置換

### デフォルト設定

* CLIモード: `warn` レベル
* MCPモード: `info` レベル
* `RUST_LOG` 環境変数による上書き可能

---

## 19. 同時実行制御

### metadata.db

* SQLite WALモードにより、複数リーダー + 単一ライターの同時アクセスをサポート
* CLIプロセス間での競合はSQLiteのビルトインロックで制御

### vault.db

* WAL無効のため、書き込み時は排他ロック
* 書き込み競合時はリトライ（最大3回、100ms間隔）

### MCPサーバー

* 単一プロセスで動作（`mcp.sock` のファイルロックで多重起動を防止）
* 内部状態はMutex / RwLockで保護

---

## 20. テスト戦略

### ユニットテスト

* 暗号化・復号ロジック
* provider設定の検証ロジック
* approval判定ロジック
* エラーコード変換

### 統合テスト

* SQLite操作（metadata.db / vault.db）
* OAuth PKCEフロー（モックサーバー使用）
* MCPプロトコルの送受信

### E2Eテスト

* CLIコマンドの実行と出力検証
* provider登録 → 認証 → API呼び出しの一連のフロー

### カバレッジ目標

* ユニットテスト: 80%以上
* 統合テスト: 主要パスを網羅

---

## 21. バージョニング・マイグレーション

### CLIバージョン

* セマンティックバージョニング（SemVer）を採用
* `mycli --version` で表示

### DBスキーマバージョン

* metadata.db / vault.db それぞれにスキーマバージョンを管理
* `schema_version` テーブルで管理

```sql
CREATE TABLE schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT
);
```

### マイグレーション

* CLI起動時にスキーマバージョンを確認し、必要に応じて自動マイグレーション
* マイグレーションはトランザクション内で実行（失敗時ロールバック）
* ダウングレードは非対応（バックアップからの復元を推奨）

---

## 22. JSON出力仕様

### 出力モード

* **デフォルト**: 人間向けフォーマット（色付き、整形済み）
* `--json`: 機械向けJSON出力（1行、色なし）
* `--json --pretty`: 機械向けJSON出力（整形済み）

### 安定性保証

* `ok`, `data`, `code`, `message` フィールドはSemVerに従い互換性を維持
* フィールドの追加は非破壊変更（マイナーバージョン）
* フィールドの削除・型変更は破壊変更（メジャーバージョン）

---

# まとめ

今の状態は：

👉 **設計方針 → 正式設計書へ整理完了**
