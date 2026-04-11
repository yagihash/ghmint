# mini-gh-sts 実装計画

## 使い方

このドキュメントを読んだ上で「Phase X を実装して」と指示することで各フェーズを実装できる。
各フェーズは順番に実行すること（後のフェーズは前のフェーズ完了を前提とする）。
実装前に必ず `CLAUDE.md` のアーキテクチャガイドも参照すること。

---

## Phase 0: パッケージ構成の整理

**目的:** コードと CLAUDE.md の記述を一致させる。

### 変更内容

#### `pkg/signer/rsa.go` → `internal/signer/rsa.go` に移動

- `pkg/signer/rsa.go` を削除
- `internal/signer/rsa.go` を新規作成（パッケージ名は `signer` のまま）
  - 内容は `pkg/signer/rsa.go` と同一
- `cmd/mini-gh-sts/main.go` のインポートを更新:
  - `github.com/yagihash/mini-gh-sts/pkg/signer` → `github.com/yagihash/mini-gh-sts/internal/signer`（RSASigner の参照のみ）
  - `pkg/signer` の `Signer` インターフェース参照は引き続き `pkg/signer` を使う

### 完了条件

- `go build ./...` が通ること
- `pkg/signer` には `Signer` インターフェース定義（`signer.go`）のみが残ること
- `internal/signer` に RSASigner 実装が存在すること

---

## Phase 1: `pkg/githubapp` リファクタ

**目的:** `TokenIssuer` を `Signer` インターフェース対応にし、`permissions` / `repositories` / `expires_at` を扱えるようにする。`AppClient`（`GetFileContent`）を削除する。

### 変更内容

#### `pkg/githubapp/token.go` を全面刷新

**現状のシグネチャ:**
```go
type TokenIssuer struct { appID string; privateKey *rsa.PrivateKey }
func New(appID string, privateKeyPath string) (*TokenIssuer, error)
func (t *TokenIssuer) Issue(ctx context.Context, owner string) (string, error)
```

**変更後のシグネチャ:**
```go
type jwtSigner interface {
    SignRS256([]byte) ([]byte, error)
}

type TokenIssuer struct {
    appID      string
    signer     jwtSigner
    httpClient *http.Client
}

// IssueResult は GitHub API から取得したトークン情報を保持する
type IssueResult struct {
    Token        string
    ExpiresAt    time.Time
    Permissions  map[string]string
    Repositories []string  // org/repo フルパス形式
}

func New(appID string, signer jwtSigner) *TokenIssuer

func (t *TokenIssuer) Issue(
    ctx context.Context,
    owner string,
    permissions map[string]string,
    repositories []string,  // org/repo フルパス形式で渡ってくる
) (IssueResult, error)
```

**実装上の注意点:**
- `signJWT()` は `t.signer.SignRS256()` を使って署名すること
- `Issue` 内で `repositories` を GitHub API に渡す際は `org/repo` → `repo` 名のみに変換すること
  - 例: `"yagihash/app"` → `"app"`
- `requestInstallationToken` は `permissions` と変換済み `repositories` を JSON ボディに含めること
  - `repositories` が空スライスの場合（全リポジトリ許可）はフィールドを省略すること
- GitHub API レスポンスから `expires_at`（RFC 3339 文字列）を `time.Time` に変換して `IssueResult.ExpiresAt` に格納すること
- `IssueResult.Repositories` はレスポンスではなく引数で受け取った `repositories`（org/repo フルパス形式）をそのまま返すこと

#### `pkg/githubapp/appclient.go` を削除

### 完了条件

- `go build ./...` が通ること（`main.go` はこの時点でビルドエラーになってよい）
- `pkg/githubapp` に `AppClient` / `GetFileContent` が存在しないこと
- `TokenIssuer` が `Signer` インターフェースを使うこと（`rsa.PrivateKey` への直接依存がないこと）

---

## Phase 2: `pkg/policystore` リファクタ

**目的:** GitHub クライアントを `pkg/policystore` 内部に閉じ込める。旧 `AppClient` のロジックを unexported 型として移動し、`NewRepoPolicyStore` のシグネチャを変更する。

### 変更内容

#### `pkg/policystore/appclient.go` を新規作成（unexported）

旧 `pkg/githubapp/appclient.go` の内容を移植する。変更点:
- 型名を `appClient`（小文字・unexported）にする
- `jwtSigner` インターフェースを `pkg/policystore` パッケージ内に定義する
- `httpClient *http.Client` フィールドを持つ
- `GetFileContent(ctx context.Context, repo, path string) ([]byte, error)` メソッドのみ公開する
- `installationID` / `installationToken` / `jwt` は unexported メソッドのまま
- `installationToken` 内の permissions のハードコード（`{"permissions":{"contents":"read"}}`）を除去し、シンプルなトークン取得に変更する（policystore はトークンの権限を気にしない）

#### `pkg/policystore/repo.go` を更新

**現状のシグネチャ:**
```go
type githubClient interface { GetFileContent(...) ([]byte, error) }
func NewRepoPolicyStore(client githubClient) *RepoPolicyStore
```

**変更後:**
```go
type jwtSigner interface {
    SignRS256([]byte) ([]byte, error)
}

type Option func(*RepoPolicyStore)

// WithHTTPClient はテスト時に httptest.Server 用クライアントを注入するためのオプション。
func WithHTTPClient(c *http.Client) Option

func NewRepoPolicyStore(appID string, signer jwtSigner, opts ...Option) *RepoPolicyStore
```

`RepoPolicyStore` は内部に `*appClient` を持つ。`Option` は `appClient` の `httpClient` フィールドを差し替える。

### 完了条件

- `go build ./...` が通ること（`main.go` はこの時点でビルドエラーになってよい）
- `pkg/policystore` が `pkg/githubapp` を import していないこと
- `pkg/policystore` パッケージ外に `githubClient` インターフェースや `appClient` 型が露出していないこと

---

## Phase 3: `pkg/server` 更新

**目的:** レスポンス仕様の変更（`expires_at` / `permissions` / `repositories` 追加）、エラーレスポンスへの `code` フィールド追加、ステータスコードの修正。

### 変更内容

#### `pkg/server/server.go` を更新

**`tokenIssuer` インターフェースの変更:**
```go
type tokenIssuer interface {
    Issue(
        ctx context.Context,
        owner string,
        permissions map[string]string,
        repositories []string,
    ) (githubapp.IssueResult, error)
}
```

**`handleToken` の変更:**

1. `policy` が空の場合に 400 を返すチェックを追加:
   ```go
   if req.Policy == "" {
       writeError(w, http.StatusBadRequest, "policy is required", "MISSING_POLICY")
       return
   }
   ```

2. OIDC 検証失敗のステータスコードを 400 → 401 に変更:
   ```go
   writeError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
   ```

3. `policyVerifier.Verify` の返す `permissions` / `repositories` を `tokenIssuer.Issue` に渡す:
   ```go
   allowed, permissions, repositories, err := s.policyVerifier.Verify(...)
   // ...
   result, err := s.tokenIssuer.Issue(r.Context(), org, permissions, repositories)
   ```

4. レスポンス JSON を更新:
   ```go
   // expires_at は time.RFC3339 形式
   // repositories は org/repo フルパス形式（IssueResult からそのまま）
   json.NewEncoder(w).Encode(struct {
       Token        string            `json:"token"`
       ExpiresAt    string            `json:"expires_at"`
       Permissions  map[string]string `json:"permissions"`
       Repositories []string          `json:"repositories"`
   }{
       Token:        result.Token,
       ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
       Permissions:  result.Permissions,
       Repositories: result.Repositories,
   })
   ```

**`writeError` のシグネチャ変更:**
```go
func writeError(w http.ResponseWriter, status int, msg, code string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    fmt.Fprintf(w, `{"error":%q,"code":%q}`, msg, code)
}
```

**全 `writeError` 呼び出しの `code` 値:**

| 呼び出し箇所 | code |
|---|---|
| Content-Type 不正 | `UNSUPPORTED_MEDIA_TYPE` |
| Authorization ヘッダー不正 | `BAD_REQUEST` |
| リクエストボディ不正 | `BAD_REQUEST` |
| scope が空 | `MISSING_SCOPE` |
| policy が空 | `MISSING_POLICY` |
| OIDC 検証失敗 | `INVALID_TOKEN` |
| ポリシー評価失敗（エラー） | `INTERNAL_ERROR` |
| ポリシー denied | `FORBIDDEN` |
| トークン発行失敗 | `INTERNAL_ERROR` |

### 完了条件

- `go build ./...` が通ること（`main.go` はこの時点でビルドエラーになってよい）
- `POST /token` に `policy` なしでリクエストすると `{"error":"policy is required","code":"MISSING_POLICY"}` が返ること
- `POST /token` に無効な OIDC トークンを送ると HTTP 401 が返ること
- 成功レスポンスに `expires_at` / `permissions` / `repositories` が含まれること

---

## Phase 4: `main.go` 配線変更

**目的:** Phase 0〜3 の新しい API に合わせて `main.go` を更新し、`go build ./...` を通す。

### 変更内容

#### `cmd/mini-gh-sts/main.go` を更新

**現状:**
```go
ti, err := githubapp.New(cfg.AppID, cfg.PrivateKeyPath)  // 削除
rs, err := signer.NewRSASignerFromFile(cfg.PrivateKeyPath)
ac := githubapp.NewAppClient(cfg.AppID, rs)  // 削除
ps := policystore.NewRepoPolicyStore(ac)
```

**変更後:**
```go
// internal/signer パッケージから RSASigner を使う（Phase 0 で移動済み）
rs, err := internalsigner.NewRSASignerFromFile(cfg.PrivateKeyPath)
if err != nil {
    fmt.Fprintf(os.Stderr, "failed to initialize signer: %v\n", err)
    return 1
}

ti := githubapp.New(cfg.AppID, rs)
ps := policystore.NewRepoPolicyStore(cfg.AppID, rs)
pv := verifier.New(ps)
```

秘密鍵の読み込みが1回になること。`githubapp.New` と `policystore.NewRepoPolicyStore` に同じ `rs` を渡す。

### 完了条件

- `go build ./...` が通ること
- `go vet ./...` が通ること

---

## Phase 5: Cloud KMS 切り替え

**目的:** 本番環境で Google Cloud KMS を使った JWT 署名に切り替える。`PRIVATE_KEY_PATH` を廃止する。

### 変更内容

#### `pkg/signer/kms.go` を新規作成

```go
package signer

import (
    "context"
    "crypto/sha256"
    "fmt"

    kms "cloud.google.com/go/kms/apiv1"
    kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// KMSSigner implements Signer using Google Cloud KMS (RSA_SIGN_PKCS1_2048_SHA256).
type KMSSigner struct {
    client  *kms.KeyManagementClient
    keyName string // projects/.../locations/.../keyRings/.../cryptoKeyVersions/...
}

func NewKMSSigner(ctx context.Context, keyName string) (*KMSSigner, error)

func (s *KMSSigner) SignRS256(data []byte) ([]byte, error)
```

`go.mod` に `cloud.google.com/go/kms` を追加すること。

#### `internal/config/config.go` を更新

```go
type Config struct {
    Port       int    `envconfig:"PORT" default:"8080"`
    Debug      bool   `envconfig:"DEBUG" default:"false"`
    Hostname   string `envconfig:"HOSTNAME" required:"true"`
    AppID      string `envconfig:"APP_ID" required:"true"`
    KMSKeyName string `envconfig:"KMS_KEY_NAME" required:"true"`
    // PrivateKeyPath は削除
}
```

#### `cmd/mini-gh-sts/main.go` を更新

```go
kmsSigner, err := signer.NewKMSSigner(ctx, cfg.KMSKeyName)
if err != nil {
    fmt.Fprintf(os.Stderr, "failed to initialize kms signer: %v\n", err)
    return 1
}

ti := githubapp.New(cfg.AppID, kmsSigner)
ps := policystore.NewRepoPolicyStore(cfg.AppID, kmsSigner)
pv := verifier.New(ps)
```

`internal/signer` のインポートを削除し、`pkg/signer` の `KMSSigner` を使う。

### 完了条件

- `go build ./...` が通ること
- Cloud Run 上で `STS_KMS_KEY_NAME` を設定して起動し、トークン発行が動作すること
- `internal/signer` パッケージへの参照が `main.go` から消えていること
