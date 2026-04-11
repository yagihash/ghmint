# mini-gh-sts アーキテクチャガイド

## 概要

任意の OIDC プロバイダーが発行した ID Token を受け取り、Rego ポリシーで検証した上で GitHub App Installation Access Token を発行する STS (Security Token Service)。

### OSS としての性質

このリポジトリは以下の二面性を持つ:

- **pluggable ライブラリ**: `Signer`・`Verifier`（+`PolicyStore`）・`Logger` を差し替えて用途に合った STS を構築できる
- **リファレンス実装**: 開発者自身が使うための実装。以下の4点が固定される:
  - Google Cloud 上で動作する
  - ポリシーは各リポジトリで管理される（集中管理ではない）
  - ポリシー言語は Rego
  - GitHub App の秘密鍵は Google Cloud KMS で管理される

### コアとして差し替え不可のもの

OIDC ID Token の検証（署名・`aud`・`exp`・`iat`）はフレームワークのコアであり、インターフェース化しない。

#### audience について

`aud` の検証には STS 自身のホスト名を使う。これは、別の STS に向けて発行されたトークンを誤処理しないためのセキュリティ上の意図による。

## パッケージ責務

| パッケージ | 責務 |
|---|---|
| `pkg/signer` | `Signer` インターフェース定義 + KMS 実装（production 用） |
| `internal/signer` | ローカル RSA 秘密鍵を使った `Signer` 実装（開発用） |
| `pkg/oidc` | OIDC JWT 検証（署名・`aud`・`exp`・`iat`）、コア・差し替え不可 |
| `pkg/verifier` | 検証済み Claims をポリシーに照らして発行可否・権限・リポジトリを決定 |
| `pkg/policystore` | `PolicyStore` インターフェース定義 + GitHub リポジトリからの Rego ファイル取得実装（GitHub クライアントは内部に閉じ込める） |
| `pkg/githubapp` | GitHub App Installation Access Token の発行のみ。`Signer` インターフェースで JWT 署名（KMS 対応）。 |
| `pkg/app` | HTTP ハンドラ・OIDC 検証・各コンポーネントの組み合わせ。サービス全体を束ねる `App` 型 |

## 依存関係

```
App
  ├─ pkg/oidc       （OIDC JWT 検証 → Claims 取得、コア）
  ├─ pkg/verifier   （Claims + scope + policy → 発行可否・permissions・repositories）
  │     └─ pkg/policystore  （Rego ファイル取得、Verifier の内部依存）
  └─ pkg/githubapp  （GitHub App Installation Access Token 発行）
```

`pkg/policystore` の `RepoPolicyStore` 実装は GitHub Contents API を使うが、そのクライアント（JWT 署名を含む）は `pkg/policystore` の内部に閉じ込める（unexported 型）。`pkg/githubapp` はトークン発行のみを担い、policystore 用クライアントとは独立している。両者はそれぞれ独自に GitHub App 認証を行う。

## App API

```go
app := app.New(appID, logger, signer, verifier)
app.Serve(addr)
```

`App` は「mini-gh-sts サービス」そのものを表す型であり、HTTP サーバーに留まらずサービスを構成するコンポーネント全体を束ねる。

## HTTP API

### エンドポイント

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/healthz` | ヘルスチェック |
| `POST` | `/token` | GitHub App Installation Access Token の発行 |

### POST /token

**リクエスト**

```
Authorization: Bearer <oidc-token>
Content-Type: application/json

{
  "scope": "<org> または <org>/<repo>",  // 必須
  "policy": "<ポリシー名>"               // 必須
}
```

**レスポンス（200 OK）**

```json
{
  "token": "ghs_...",
  "expires_at": "2026-04-11T15:00:00Z",
  "permissions": {"contents": "read"},
  "repositories": ["yagihash/app"]   // org/repo フルパス形式
}
```

**エラーレスポンス**

```json
{"error": "<メッセージ>", "code": "<機械可読コード>"}
```

**ステータスコードと `code` 値**

| HTTP | `code` | 状況 |
|---|---|---|
| 400 | `BAD_REQUEST` | リクエストボディが不正 |
| 400 | `MISSING_SCOPE` | `scope` が空 |
| 400 | `MISSING_POLICY` | `policy` が空 |
| 401 | `INVALID_TOKEN` | OIDC トークン無効/期限切れ |
| 403 | `FORBIDDEN` | 発行不可（後述の fail-closed 方針を参照） |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Content-Type が application/json でない |
| 500 | `INTERNAL_ERROR` | 内部エラー |

#### fail-closed 方針

403 はポリシーが deny した場合だけでなく、ポリシーが存在しない・Rego 構文エラー・必須ルール欠如・`scope=org/repo` なのに `repositories` が defined など、ポリシー起因のあらゆる失敗に統一して使う。
任意の OIDC プロバイダーを受け入れる設計上、有効なトークン保持者がポリシーの存在を列挙できてしまう問題への対策。詳細はサーバーログで確認する。

> **議論の余地あり:**
> - ポリシーが存在しない場合に 404 を返す案（DX 向上、ただしポリシー存在のリークになる）
> - ポリシーが不正な場合に 500 を返す案（サーバーサイドの設定ミスを明示できる、ただし同様にリークになる）

## Verifier インターフェース

```go
type Verifier interface {
    Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (ok bool, permissions map[string]string, repositories []string, err error)
}
```

- `claims`: OIDC 検証済みの ID Token 全クレーム（`minioidc.Claims.Raw`）
- `scope`: `<org>` または `<org>/<repo>` 形式
- `policy`: ポリシー名（例: `"test-policy"`）

## PolicyStore インターフェース

```go
type PolicyStore interface {
    Fetch(ctx context.Context, scope string, policy string) ([]byte, error)
}
```

### scope → リポジトリのマッピング

PolicyStore は scope に `.github/mini-gh-sts/<policy>.rego` を付けてファイルを取得する:

```
scope="yagihash/mini-gh-sts" → yagihash/mini-gh-sts リポジトリの .github/mini-gh-sts/<policy>.rego
scope="yagihash"             → yagihash/.github リポジトリの .github/mini-gh-sts/<policy>.rego
```

org のみの scope は、org 配下の複数リポジトリへのアクセスをまとめて許可するポリシーを `<org>/.github` リポジトリに置く想定。

## Rego ポリシーの契約

パッケージ名は `mini_gh_sts`。`input` には ID Token の全クレームが渡される（`sub`, `repository`, `ref`, `workflow` 等）。

### フレームワークが評価するルール

| ルール | 必須 | 説明 |
|---|---|---|
| `data.mini_gh_sts.issuer` | **必須** | 許可する OIDC Issuer。フレームワークが `input.iss` と照合する。未定義なら deny。 |
| `data.mini_gh_sts.permissions` | **必須** | 発行する Installation Token に付与する権限。未定義ならエラー。 |
| `data.mini_gh_sts.allow` | **必須** | 発行可否。`true` でなければ deny。 |
| `data.mini_gh_sts.repositories` | 省略可 | アクセスを許可するリポジトリ一覧。省略時はデフォルト動作（後述）。 |

### issuer について

1つのポリシーファイルで許可できる issuer は1つ。複数の OIDC プロバイダーを許可したい場合はポリシーを分ける。

### repositories の挙動

| ポリシーの定義 | 挙動 |
|---|---|
| 未定義（undefined） | ポリシーファイルの置き場所リポジトリのみ（scope に対応するリポジトリ） |
| `[]`（空配列） | GitHub App がアクセス可能な全リポジトリ（制限なし） |
| `["org/a", "org/b"]` | 指定したリポジトリのみ |

**`scope=<org>/<repo>` の場合**: `repositories` がポリシー内で定義されていたらエラー。必ず undefined にして、単一リポジトリ（scope のリポジトリ）のみに絞られる動作を使う。

**`scope=<org>` + undefined の場合**: デフォルトは `<org>/.github` になる。これは仕様上の一貫性として受け入れているトレードオフ。org スコープで複数リポジトリにアクセスしたい場合は `repositories` を明示する。

### ポリシー例

```rego
package mini_gh_sts

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

allow if {
    input.repository == "yagihash/app"
    input.ref == "refs/heads/main"
}
```

## linter

ポリシーファイルを静的検証する linter を提供する。

- **バイナリ** (`mini-gh-sts-lint`): ローカル実行用
- **GitHub Action**: CI 組み込み用（バイナリを内部で呼び出す）

検証内容:
- `issuer`・`permissions`・`allow` の存在
- `permissions` のキー・値が GitHub App の有効な権限名であること
- `scope=org/repo` 向けポリシーで `repositories` が定義されていないこと（静的解析の範囲で）

## デプロイモデル（リファレンス実装）

- **実行環境**: Google Cloud Run
- **ロギング**: Cloud Logging
- **秘密鍵管理**: Google Cloud KMS（開発時は RSA ファイル signer も使用、将来 KMS に一本化予定）
