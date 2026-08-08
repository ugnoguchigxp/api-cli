---
name: api-cli MCP Interaction
description: api-cli MCPでレビュー済みActionDefinitionから生成されたToolを安全に実行するためのスキル
---

# api-cli MCP Interaction Skill

このスキルは、`api-cli` MCPサーバーが公開する、明示的に許可されたAction Toolを利用するためのガイドラインです。

## 概要

`api-cli` は認証情報をMCPクライアントへ渡さず、`enabled: true`のActionDefinitionだけをToolとして公開します。MCPクライアントはprovider、任意method、任意pathを指定できません。

## 利用可能なツール

Tool名、入力schema、出力schemaはActionDefinitionから生成されます。Tool一覧を取得し、目的に一致する
Actionだけを選んでください。汎用`api_call`と`list_providers`は公開されません。

## 重要なガイダンス

### 1. セキュリティと明示的な承認
- **書き込み確認**: write ActionはMCP elicitationで、正規化された全引数に結び付いた一回限りの確認を要求します。入力を変更した場合は新しい確認が必要です。
- **機密情報の保護**: API レスポンスにトークンや個人情報、接続シークレットが含まれる可能性があります。これらを不必要にログに出力したり、ユーザーへの回答に含めたりしないでください。

### 2. 認証エラーのハンドリング
- **AuthRequired / AuthExpired**: 認証が必要または期限切れの場合、AI は直接解決できません。
  - **アクション**: ユーザーに `api-cli auth login <provider_id>` を実行して認証を更新するように依頼してください。

### 3. エラー時の扱い
- `schema_validation`はAction schemaに従って入力を修正します。
- `upstream_result_unknown`は書き込み結果が不明なため、自動再試行しません。
- Tool一覧にない操作を、別名や任意HTTPで迂回しません。

## 利用例

### シナリオ: 顧客情報を取得する
1. Tool一覧から、説明とschemaが目的に一致する`customer.get`等のread Actionを選ぶ。
2. schemaで要求された`customer_id`だけを渡す。
3. マスキング済みの結果を必要な範囲だけ要約する。
