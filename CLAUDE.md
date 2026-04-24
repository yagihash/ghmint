# ghmint アーキテクチャガイド

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
| `pkg/signer` | `Signer` インターフェース定義のみ |
| `pkg/signer/kms` | KMS を使った `Signer` 実装（production 用）。`Close()` で gRPC クライアントを解放する |
| `internal/signer` | ローカル RSA 秘密鍵を使った `Signer` 実装（開発用） |
| `internal/oidc` | OIDC JWT 検証（署名・`aud`・`exp`・`iat`）、コア・差し替え不可 |
| `pkg/verifier` | `Verifier` インターフェース定義 + `DenialError` 型 |
| `pkg/verifier/rego` | Rego ポリシーを使った `Verifier` 実装。評価は 5 秒タイムアウト付き |
| `pkg/policystore` | `PolicyStore` インターフェース定義のみ |
| `pkg/policystore/github` | GitHub リポジトリから Rego ファイルを取得する `PolicyStore` 実装。`pkg/installation.Client` を使って認証する |
| `pkg/installation` | GitHub App 認証クライアント。JWT 署名・installation ID・installation token 取得（キャッシュ付き）を提供。`TokenForOwner(ctx, owner) (string, error)` が主要 API |
| `internal/tokenissuer` | GitHub App Installation Access Token の発行のみ。`pkg/installation.Client` を使って認証し、permissions・repositories を指定してトークンを発行する |
| `internal/webhook` | GitHub `pull_request` webhook を受信し、`.github/ghmint/*.rego` の静的バリデーションを行い、GitHub Checks API で結果を報告する |
| `pkg/app` | サービス全体を束ねる `App` 型。OIDC 検証・Token 発行・HTTP サーバーを内部で構築する。HTTP ハンドラは unexported |
| `tools/gen-permissions` | GitHub REST API OpenAPI spec（`components/schemas/app-permissions`）から `internal/webhook/permissions_gen.go` を生成する |

## 依存関係

```
App (pkg/app)
  ├─ internal/oidc              （OIDC JWT 検証 → Claims 取得、コア）
  ├─ pkg/verifier               （Verifier インターフェース + DenialError）
  └─ internal/tokenissuer       （GitHub App Installation Access Token 発行）
       └─ pkg/installation      （GitHub App 認証・キャッシュ）

main.go が組み立てる実装:
  pkg/signer/kms                → pkg/signer.Signer を満たす
  pkg/installation              → installation.Client を1つ生成し全コンポーネントで共有
  pkg/policystore/github        → pkg/policystore.PolicyStore を満たす（installation.Client を受け取る）
  pkg/verifier/rego             → pkg/verifier.Verifier を満たす
    └─ pkg/policystore/github   （Rego ファイル取得）
  internal/webhook              → WebhookHandler（installation.Client を受け取る）
```

`pkg/installation.Client` は `main.go` で1インスタンスだけ生成し、`internal/tokenissuer`・`pkg/policystore/github`・`internal/webhook` に注入する。これにより installation ID・installation token のキャッシュが全コンポーネントで共有される。

### pkg/installation のキャッシュ設計

| エントリ | キャッシュキー | TTL | 用途 |
|---|---|---|---|
| installation ID | `owner` | 60 分 | GitHub App installation の数値 ID |
| plain token | `owner` | `expires_at` - 5 分 | policystore・webhook 用の汎用 API トークン |
| policy content | `repo:path` | 60 秒 | Rego ファイルのバイト列（`pkg/policystore/github` が管理） |

コールドキャッシュ時も JWT 署名（KMS 呼び出し）は1回のみ（installation ID 取得とトークン発行で同一 JWT を再利用）。

#### ユーザー向けトークン発行（`IssueToken`）はキャッシュしない

`/token` エンドポイントで最終的にユーザーへ返す Installation Access Token（`IssueToken` が発行するもの）は **キャッシュされない**。呼び出しのたびに GitHub API を叩いて新しいトークンを取得する。

これは、ユーザーに返すトークンの `permissions` と `repositories` がリクエストごとの Rego 評価結果に基づくため、同一の結果をキャッシュして別リクエストに流用することが正しくないからである。

#### 異なるコンテキスト間でのキャッシュ悪用は不可

plain token（`TokenForOwner`）のキャッシュは `owner` キーで共有されるが、これはポリシーファイルの取得（policystore）や check run の作成（webhook）など **App 自身の内部操作にのみ使う**。ユーザーには返さない。

ユーザー A と B が同じ org に対してリクエストした場合:
- plain token（ポリシーファイル取得用）→ **共有** される（問題なし。App レベルの読み取りであり、ユーザーのアイデンティティと無関係）
- Rego ポリシー評価 → **共有されない**（各リクエストの OIDC クレームで独立して評価）
- ユーザーへ返す permissioned token → **共有されない**（毎回 GitHub API を叩いて発行）

## App API

```go
cfg := app.Config{
    AppID:          "123456",
    Audience:       "sts.example.com",
    Signer:         kmsSigner,
    Verifier:       regoVerifier,
    Logger:         logger,
    WebhookHandler: webhookHandler, // オプション: nil なら /webhook ルート未登録
    // オプション: ReadTimeout, WriteTimeout, IdleTimeout など
}
a, err := app.New(cfg)
if err != nil {
    // cfg.Validate() の失敗（必須フィールド未設定など）
}
a.Serve(":8080")
```

`App` は「ghmint サービス」そのものを表す型であり、HTTP サーバーに留まらずサービスを構成するコンポーネント全体を束ねる。`app.Config` は `Validate()` メソッドを持ち、`app.New` の内部で呼ばれる。複数フィールドの検証エラーは `errors.Join` でまとめて返す。

`WebhookHandler` は `http.Handler` として pluggable。`Signer`・`Verifier` と同じ注入パターン。`pkg/app` は `internal/webhook` を import しない。

## HTTP API

### エンドポイント

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/healthz` | ヘルスチェック |
| `POST` | `/token` | GitHub App Installation Access Token の発行 |
| `POST` | `/webhook` | GitHub pull_request webhook 受信（`WebhookHandler` が設定されている場合のみ） |

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

レスポンスには `Cache-Control: no-store` を付与する。

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

実装上は `Verifier.Verify` が `*verifier.DenialError` を返した場合に 403 を返す。`DenialError` は人間向けの `Reason` フィールドを持ち、サーバーログに記録する。クライアントには理由を開示しない。

```go
// pkg/verifier
type DenialError struct {
    Reason string // サーバーログ用。クライアントには返さない
}
```

### POST /webhook

`X-Hub-Signature-256` で HMAC-SHA256 署名を検証し、`pull_request` の `opened`/`synchronize`/`reopened` アクションのみ処理する。202 Accepted を即座に返し、バリデーションは goroutine で非同期実行する。

`.github/ghmint/*.rego` に変更がない PR は check run を作成しない。

**バリデーション内容**:
1. Rego 構文チェック（`ast.ParseModule`）
2. `package ghmint` 宣言の確認
3. `issuer`・`allow`・`permissions` 必須ルールの存在確認
4. `permissions` の key-value 検証（OpenAPI spec 由来のリスト、per-permission の allowed values）
5. `.github` リポジトリ以外のポリシーで `repositories` ルールが定義されていないかの確認

`permissions` の valid な key-value は `tools/gen-permissions` で GitHub REST API OpenAPI spec（`components/schemas/app-permissions`）から生成し、`internal/webhook/permissions_gen.go` に保存する。毎週月曜に `.github/workflows/update-permissions.yml` が自動更新する。

Check Run 名: `ghmint / policy validation`

**設定**:
- `STS_WEBHOOK_SECRET` 環境変数が未設定の場合、`/webhook` ルートは登録されない

## Verifier インターフェース

```go
type Verifier interface {
    Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}
```

- `claims`: OIDC 検証済みの ID Token 全クレーム（`internal/oidc.Claims.Raw`）
- `scope`: `<org>` または `<org>/<repo>` 形式
- `policy`: ポリシー名（例: `"test-policy"`）

`ok bool` は持たない。発行不可の場合は `*verifier.DenialError` を `err` として返す。内部エラー（ネットワーク障害・OPA 実行エラー等）は通常の `error` で返す。呼び出し側は `errors.As(err, &denialErr)` で区別する。

## Signer インターフェース

```go
type Signer interface {
    SignRS256(ctx context.Context, data []byte) ([]byte, error)
}
```

`ctx` は KMS API 呼び出しなどの非同期処理でキャンセルを伝播させるために必須。`internal/signer` の RSA 実装は `ctx` を無視してよい（ローカル処理のため）。

`pkg/signer/kms` の実装は `Close()` メソッドを持ち、gRPC クライアントを解放する。`Close()` 後の `SignRS256` 呼び出しは `ErrSignerClosed` を返す。

## PolicyStore インターフェース

```go
type PolicyStore interface {
    Fetch(ctx context.Context, scope string, policy string) ([]byte, error)
}
```

## Rego ポリシーの契約

パッケージ名は `ghmint`。`input` には ID Token の全クレームが渡される（`sub`, `repository`, `ref`, `workflow` 等）。

### フレームワークが評価するルール

| ルール | 必須 | 説明 |
|---|---|---|
| `data.ghmint.issuer` | **必須** | 許可する OIDC Issuer。フレームワークが `input.iss` と照合する。未定義なら deny。 |
| `data.ghmint.permissions` | **必須** | 発行する Installation Token に付与する権限。未定義ならエラー。 |
| `data.ghmint.allow` | **必須** | 発行可否。`true` でなければ deny。`false` と undefined は区別してログに記録する（前者はポリシーが明示的に拒否、後者はポリシーの設定ミス）。 |
| `data.ghmint.repositories` | 省略可 | アクセスを許可するリポジトリ一覧。省略時はデフォルト動作（後述）。 |

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
package ghmint

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}

allow if {
    input.repository == "yagihash/app"
    input.ref == "refs/heads/main"
}
```

## デプロイモデル（リファレンス実装）

- **実行環境**: Google Cloud Run
- **ロギング**: Cloud Logging
- **秘密鍵管理**: Google Cloud KMS（開発時は `internal/signer` の RSA ファイル signer を使用）
- **コンテナ**: `gcr.io/distroless/static-debian12:nonroot`（UPX 圧縮あり）
