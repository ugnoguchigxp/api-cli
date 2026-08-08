# apicli（TypeScript サーバーパッケージ）

`apicli` は、TypeScript バックエンド向けのフレームワーク非依存 API クライアントコアです。

同じコアコードを、Express / Nest / Fastify / Hono / Next.js の各ハンドラから利用できるように設計しています。

## 設計方針

- コアロジックをフレームワーク非依存に保つ
- 既存のサーバー認証（JWT / session など）はアダプター経由で再利用する
- 役割を明確に分離する
  - `ProviderResolver`: 呼び出し先 API プロバイダ設定を解決
  - `AuthAdapter`: 外部 API への認証ヘッダーを解決
  - `ApiClient`: HTTP 実行、タイムアウト、レスポンス解析、エラー正規化

## この構成にする理由

- 特定フレームワークへのロックインを避ける
- Express/Nest/Fastify/Hono/Next.js 間の移行コストを下げる
- サービス横断で API 連携ロジックを共通化する

## インストール

```bash
npm install apicli
```

## 最小コード導入（推奨）

設定駆動の `createApiProxyServer` を使うと、導入先コードを最小化できます。

```ts
import { createApiProxyServer } from 'apicli';

const proxy = createApiProxyServer({
  providers: {
    billing: {
      id: 'billing',
      baseUrl: 'https://billing.example.com'
    }
  },
  auth: {
    mode: 'forward-header',
    sourceHeaderName: 'authorization',
    targetHeaderName: 'authorization'
  },
  allowedMethods: ['GET'],
  allowedPathPrefixes: ['/v1/invoices'],
  limits: {
    maxRequestBytes: 1048576,
    maxResponseBytes: 1048576,
    maxErrorBytes: 65536
  }
});
```

proxyは既定で`GET`/`HEAD`だけを許可し、path policyの指定を必須とします。任意pathを
許可する`dangerouslyAllowAnyTargetPath`は、上流credentialで到達できる全APIを呼び出し元へ
公開するため、信頼済み・認証済みの内部用途以外では使用しないでください。redirectは追従せず、
request/response/error bodyは上限を超えると拒否されます。
`localhost`やprivate/special-purpose IPは既定で拒否され、内部APIを意図して公開するproviderだけ
`allowPrivateNetwork: true`を設定します。既定のHTTP実装はhostnameを接続時に解決し、解決候補に
private/special-purpose addressが1件でも含まれる場合は接続を拒否します。独自の`fetchImpl`を
注入する場合は、このDNS検証を含むegress policyを実装側で保証してください。provider設定自体も
信頼済み管理面からのみ更新してください。cleartext HTTPの開発用例外は、DNSで意味が変わり得る
`localhost`ではなく、明示的なloopback IP（`127.0.0.1`または`[::1]`）だけに限定されます。

`parseAs: 'raw'`ではバイナリbodyを文字列化せず転送します。転送時は`set-cookie`、
`content-length`、`content-encoding`など、再構築後のbodyと不整合またはhop-by-hopとなるheaderを
除去します。

### ワンライナー導入

- Express: `app.use('/apicli', proxy.createExpressMiddleware())`
- Fastify: `fastify.all('/apicli/*', proxy.createFastifyHandler())`
- NestJS: Controller 内で `return proxy.createNestHandler()(req, res)`
- Hono: `app.all('/apicli/*', proxy.createHonoHandler())`
- Next.js: `export const { GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS } = proxy.createNextRouteHandlers()`

## コア利用例

```ts
import { ApiClient, createBearerAuthAdapter, createStaticProviderResolver } from 'apicli';

const client = new ApiClient({
  providerResolver: createStaticProviderResolver({
    billing: {
      id: 'billing',
      baseUrl: 'https://billing.example.com',
      timeoutMs: 5000,
      defaultHeaders: { 'x-service': 'backend-api' }
    }
  }),
  authAdapter: createBearerAuthAdapter(({ context }) => {
    // 既存の認証/セッション管理からトークンを取得
    return context?.metadata?.accessToken as string | undefined;
  })
});

const response = await client.call<{ ok: boolean }>({
  providerId: 'billing',
  method: 'POST',
  path: '/v1/invoices',
  body: { amount: 1000 },
  context: {
    tenantId: 't1',
    userId: 'u1',
    metadata: { accessToken: '...' }
  }
});
```

## 「APIごとの個別定義」は必須ではありません

- `apicli` は `method + path + query + body` をそのまま渡せる汎用クライアントです
- ルートごとのスキーマ/関数定義を毎回作らなくても利用できます
- 型安全を強化したい箇所だけ、後から型定義を追加する運用が可能です

## フレームワーク別の利用例

### Express

```ts
import { createContextFromNodeRequest } from 'apicli';

app.post('/api/proxy', async (req, res) => {
  const context = createContextFromNodeRequest(req);
  const result = await client.call({
    providerId: 'billing',
    method: 'GET',
    path: '/v1/invoices',
    context
  });
  res.status(result.status).json(result.data);
});
```

### NestJS

```ts
import { createContextFromNodeRequest } from 'apicli';

const context = createContextFromNodeRequest(req);
return this.apiClient.call({ providerId: 'billing', method: 'GET', path: '/v1/invoices', context });
```

### Fastify

```ts
import { createContextFromNodeRequest } from 'apicli';

const context = createContextFromNodeRequest({ headers: request.headers as Record<string, string> });
const result = await client.call({ providerId: 'billing', method: 'GET', path: '/v1/invoices', context });
reply.code(result.status).send(result.data);
```

### Hono

```ts
import { createContextFromWebRequest } from 'apicli';

app.get('/proxy', async (c) => {
  const context = createContextFromWebRequest(c.req.raw);
  const result = await client.call({ providerId: 'billing', method: 'GET', path: '/v1/invoices', context });
  return c.json(result.data, result.status);
});
```

### Next.js Route Handler

```ts
import { createContextFromWebRequest } from 'apicli';

export async function GET(request: Request) {
  const context = createContextFromWebRequest(request);
  const result = await client.call({ providerId: 'billing', method: 'GET', path: '/v1/invoices', context });
  return Response.json(result.data, { status: result.status });
}
```

## スクリプト

```bash
npm run build
npm run typecheck
npm run lint
npm run test:coverage
npm test
```

## 補足

- このパッケージは「外部 API 呼び出し」を扱うもので、サーバー自身のユーザー認証を置き換えるものではありません
- トークン保存/更新方針は既存の認証レイヤーで管理し、`AuthAdapter` で接続してください
