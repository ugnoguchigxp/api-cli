# api-cli 運用ガイド

## 配置モデル

ローカル利用では`api-cli mcp serve`（stdio）を使います。Remote MCPはloopbackで起動し、TLSを
終端するreverse proxyの背後へ配置するのが既定モデルです。non-loopbackの平文listenerは
`--allow-insecure-http`なしでは起動しません。

複数instanceでは`--redis-url-env`を必ず指定し、全instanceで同じ`--redis-key-prefix`と
`--session-ttl-seconds`を使います。RedisはMCP initialize state、認証主体とのsession binding、
active session集合、主体別token bucketを共有します。非loopback接続には`rediss://`が必須です。
Redis URLはcredentialを含み得るため、コマンドラインへ直接渡さず指定した環境変数からだけ読みます。
平文のloopback接続では、DNSで意味が変わり得る`localhost`ではなく`127.0.0.1`または`[::1]`を
指定します。

Remote principalの上流credentialは管理者CLIで事前プロビジョニングします。`principal_id`と
`tenant_id`はtoken introspectionが返す値と完全一致させ、両方を同時指定します。

```bash
printf '%s' "$REMOTE_API_KEY" | api-cli auth login crm --api-key-stdin \
  --principal-id user-123 --tenant-id tenant-1
```

## 上限

- HTTP request body: 既定1 MiB、最大16 MiB
- 同時処理: 既定64
- active MCP session: 既定1024
- 主体別rate: 既定120 requests/minute、burst 30
- session/identity binding TTL: 既定600秒、60〜86400秒
- Action response: ActionDefinitionごとの上限、最大16 MiB
- 上流API request body: 1 MiB

rate超過は`429 Too Many Requests`と`Retry-After`、Redis障害はfail-closedで
`503 Service Unavailable`を返します。書き込み結果が不明な場合は自動再試行しません。
rate-limit主体bucketの同時保持数も`max_sessions`で制限し、TTL経過後にlocal/Redis stateから
除去します。

## 監査

監査行には主体、tenant、client、Action/version、provider、risk、outcome、error code、
definition/arguments digestを記録します。token、API key、入力本文は保存しません。

```bash
api-cli audit list --limit 100
api-cli audit list --action customer.update --outcome failed
api-cli --json audit show <event-id>
```

JSON成功出力は`{"ok":true,"data":...}`、失敗はstderrの単一文書
`{"ok":false,"error":{"code":"...","message":"..."}}`です。

## 秘密鍵とバックアップ

新規環境のVault master keyはOS Keychain / Credential Manager / Secret Serviceへ保存します。
OS保護領域がない場合、または既存の`vault.key`がある場合はpermissionを制限したfile backendを
使います。ヘッドレス環境で明示的にfile backendを使う場合は
`API_CLI_VAULT_KEY_BACKEND=file`を設定します。
`vault.keyring` markerがある環境では、OS credential storeが一時的に使えない場合やentryが消失した
場合に代替鍵を生成せず起動を拒否します。これにより一時障害によるVaultの復号不能化を防ぎます。

バックアップは`metadata.db`、`vault.db`、ActionDefinitionを一貫した時点で取得してください。
file backendでは`vault.key`も必要です。OS credential store利用時は、DBだけを別ホストへ復元しても
復号できません。鍵のexportを自動化せず、組織のsecret/KMS運用へ合わせて再接続してください。

## 更新前検証

```bash
make check-all
cargo audit
cargo package --locked
cd server && npm audit && npm pack --dry-run
```

新しいbinaryがDB schemaを読めることを確認してから切り替えます。未対応の新しいschemaを検出した
旧binaryは起動を拒否します。
