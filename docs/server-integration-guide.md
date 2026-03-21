# API サーバー連携ガイド

このドキュメントでは、`api-cli` と連携するために **API サーバー側で満たすべき要件** を説明します。

---

## 認証方式

`api-cli` は以下の2種類の認証方式をサポートしています。  
API サーバーは、少なくとも一方に対応する必要があります。

### 1. API Key 認証

最もシンプルな方式です。

#### サーバー側の要件

- すべてのリクエストの `Authorization` ヘッダーに **Bearer トークン** として API Key が送信されます。
- サーバーはこのヘッダーを検証してください。

```
Authorization: Bearer <api-key>
```

> [!NOTE]
> `api-cli` は常に `Authorization: Bearer <token>` 形式で送信します。  
> Basic 認証やカスタムヘッダー（`X-API-Key` 等）には現在対応していません。

---

### 2. OAuth2 PKCE 認証

ブラウザ経由のログインフローです。

#### サーバー側の要件

OAuth2 Authorization Code Flow with PKCE ([RFC 7636](https://tools.ietf.org/html/rfc7636)) を実装してください。

##### 認可エンドポイント (`auth_url`)

以下のクエリパラメータを受け付ける必要があります:

| パラメータ | 説明 |
|-----------|------|
| `response_type` | 常に `code` |
| `client_id` | クライアント識別子 |
| `redirect_uri` | コールバックURL（`http://127.0.0.1:<port>/callback`） |
| `scope` | スペース区切りのスコープ文字列 |
| `state` | CSRF防止用のランダム文字列 |
| `code_challenge` | PKCE チャレンジ（SHA-256 + BASE64URL） |
| `code_challenge_method` | 常に `S256` |

認可成功後、ユーザーを `redirect_uri` にリダイレクトし、クエリパラメータとして `code` と `state` を返してください。

```
HTTP 302 Location: http://127.0.0.1:<port>/callback?code=<auth_code>&state=<state>
```

##### トークンエンドポイント (`token_url`)

**認可コードの交換**（`grant_type=authorization_code`）:

リクエスト（`application/x-www-form-urlencoded`）:

| パラメータ | 説明 |
|-----------|------|
| `grant_type` | `authorization_code` |
| `code` | 認可エンドポイントから受け取ったコード |
| `redirect_uri` | 認可リクエストと同じURI |
| `client_id` | クライアント識別子 |
| `code_verifier` | PKCE 検証値（`code_challenge` の元の値） |

レスポンス（`application/json`）:

```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "dGhpcyBpcyBh...",
  "expires_in": 3600
}
```

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `access_token` | ✅ | アクセストークン |
| `refresh_token` | 推奨 | リフレッシュトークン（省略可だが、省略時は自動更新不可） |
| `expires_in` | 推奨 | 有効期限（秒）。省略時は期限切れ自動検出が無効になる |

**トークンのリフレッシュ**（`grant_type=refresh_token`）:

リクエスト（`application/x-www-form-urlencoded`）:

| パラメータ | 説明 |
|-----------|------|
| `grant_type` | `refresh_token` |
| `refresh_token` | 以前発行されたリフレッシュトークン |
| `client_id` | クライアント識別子 |

レスポンスは認可コード交換と同じ形式です。新しい `refresh_token` が返されない場合、`api-cli` は既存のリフレッシュトークンを継続使用します。

---

## API エンドポイントの要件

### リクエスト形式

`api-cli` は以下の形式で API リクエストを送信します:

- **認証**: `Authorization: Bearer <access_token>` ヘッダー
- **Content-Type**: ボディがある場合は `application/json`
- **HTTP メソッド**: `GET`, `POST`, `PUT`, `DELETE`, `PATCH` に対応

### レスポンス形式

- **推奨**: JSON 形式（`application/json`）のレスポンスを返してください。
- JSON 以外のレスポンスも受信可能ですが、その場合はプレーンテキストとして扱われます。

### エラーレスポンス

- HTTP ステータスコードで成功（`2xx`）/ 失敗（`4xx`, `5xx`）を区別してください。
- `api-cli` はステータスコードとレスポンスボディをそのままユーザーに表示します。

---

## OAuth クライアントの登録

API サーバーの OAuth 管理画面で、以下の設定でクライアントを登録してください:

| 項目 | 値 |
|------|------|
| **クライアント種別** | Public Client（クライアントシークレットなし） |
| **リダイレクトURI** | `http://127.0.0.1:8080/callback`（※下記参照） |
| **許可するグラント** | `authorization_code`, `refresh_token` |
| **PKCE** | 必須（`S256`） |

> [!IMPORTANT]
> `api-cli` はローカルコールバックサーバーに動的ポートを使用する場合があります。  
> 多くの OAuth プロバイダーでは、リダイレクトURIに `http://127.0.0.1` のワイルドカードポートを許可する設定が可能です。  
> 固定ポートのみ登録可能な場合は `8080` を使用してください。

---

## チェックリスト

API サーバーが `api-cli` と連携するための最低限の要件:

### API Key 認証の場合

- [ ] `Authorization: Bearer <key>` ヘッダーを検証できる
- [ ] JSON レスポンスを返す

### OAuth PKCE 認証の場合

- [ ] PKCE（`S256`）対応の認可エンドポイントがある
- [ ] `application/x-www-form-urlencoded` 形式のトークンエンドポイントがある
- [ ] トークンレスポンスに `access_token` を含む
- [ ] リダイレクトURIに `http://127.0.0.1` のローカルアドレスを許可している
- [ ] Public Client（クライアントシークレット不要）をサポートしている
