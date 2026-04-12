# mini-gh-sts 実装改善計画

CLAUDE.md の仕様と現在の実装のギャップを解消するための計画。
「このファイルに対応して」と伝えるだけで Claude Code が実装できる粒度で記述する。

---

## 実装順序（必ず守ること）

1. **Issue 1-B** → `pkg/policyerrors/errors.go` 作成（後続の変更の前提）
2. **Issue 1-A, 1-A'** → `pkg/verifier/verifier.go` + `rego.go` 書き換え
3. **Issue 1-C** → `.github/mini-gh-sts/` のテスト用ポリシーファイル更新
4. **Issue 1-D** → `pkg/server/server.go` エラー判定修正
5. **Issue 3** → Signer インターフェースの context 対応（A〜E の順で）
6. **Issue 7** → `pkg/app` 新設（`pkg/server` を統合）+ `main.go` 書き換え + `pkg/server/` 削除
7. **Issue 2** → CLAUDE.md の記述修正（Issue 7 完了後に行う）
8. **Issue 5** → テスト追加
9. **Issue 6** → ログ設計（既存実装の分析後に着手）
10. **Issue 4** → linter（ゼロから再設計、別途計画）

Issue 1（P0）を最優先とする。Issue 3 以降は Issue 1 完了後に着手すること。

---

## Issue 1（P0）: RegoVerifier の実装不完全

### 問題

`pkg/verifier/rego.go` の `Verify()` が `data.mini_gh_sts.allow` のみを評価し、
常に `(allow, nil, nil, nil)` を返している。

**セキュリティ上の影響:**

- `permissions=nil` が `pkg/githubapp/token.go` に渡される
  → `reqBody` の `json:"permissions,omitempty"` により JSON から omit
  → GitHub App Installation の **全権限** が付与されてしまう
- `repositories=nil` が渡される
  → 同様に omit → **全リポジトリ** にアクセス可能になる
- `issuer` 未検証
  → ポリシーで宣言した OIDC Issuer と実際の `iss` クレームが一致しなくても通過する

### 修正 1-A: `pkg/verifier/verifier.go` のインターフェースを変更する

`ok bool` を削除し、deny は常に `policyerrors.DenialError` で返す設計に変更する:

```go
package verifier

import "context"

type Verifier interface {
	// Verify は OIDC 検証済みの claims をポリシーで評価し、
	// 発行する permissions と repositories を返す。
	// deny・設定ミスを含むあらゆる失敗は *policyerrors.DenialError として返す。
	// それ以外の error は内部エラー（500）として扱われる。
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}
```

### 修正 1-A': `pkg/verifier/rego.go` を書き換える

現在のファイルを以下の内容に **完全に置き換える**:

```go
package verifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/yagihash/mini-gh-sts/pkg/policyerrors"
	"github.com/yagihash/mini-gh-sts/pkg/policystore"
)

// RegoVerifier evaluates verified OIDC claims against a Rego policy fetched from PolicyStore.
// OIDC JWT verification (signature, aud, exp, iat) is the caller's responsibility.
type RegoVerifier struct {
	store policystore.PolicyStore
}

func New(store policystore.PolicyStore) *RegoVerifier {
	return &RegoVerifier{store: store}
}

func (v *RegoVerifier) Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (map[string]string, []string, error) {
	content, err := v.store.Fetch(ctx, scope, policy)
	if err != nil {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("fetch policy: %v", err)}
	}

	// data.mini_gh_sts を 1 クエリで丸ごと取得する。
	// 定義されていないルールはマップのキーに現れないため、
	// repositories の undefined vs 定義済み空配列を正しく判定できる。
	rs, err := rego.New(
		rego.Query("data.mini_gh_sts"),
		rego.Module("policy.rego", string(content)),
		rego.Input(claims),
	).Eval(ctx)
	if err != nil {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("evaluate policy: %v", err)}
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: data.mini_gh_sts is undefined (check package declaration)"}
	}
	p, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: data.mini_gh_sts has unexpected type %T", rs[0].Expressions[0].Value)}
	}

	// 1. issuer の検証（必須ルール）
	issuerVal, issuerExists := p["issuer"]
	if !issuerExists {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: issuer is undefined"}
	}
	issuer, ok := issuerVal.(string)
	if !ok {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: issuer has unexpected type %T", issuerVal)}
	}
	claimIss, _ := claims["iss"].(string)
	if claimIss != issuer {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: issuer mismatch (expected: %s, got: %s)", issuer, claimIss)}
	}

	// 2. allow の評価（必須ルール）
	// undefined は設定ミス → DenialError（reason あり）
	// false は通常の deny → DenialError（reason あり、ログで区別可能）
	allowVal, allowExists := p["allow"]
	if !allowExists {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: allow is undefined"}
	}
	allow, _ := allowVal.(bool)
	if !allow {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: allow is false"}
	}

	// 3. permissions の取得（必須ルール）
	permVal, permExists := p["permissions"]
	if !permExists {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: permissions is undefined"}
	}
	permRaw, ok := permVal.(map[string]interface{})
	if !ok {
		return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: permissions has unexpected type %T", permVal)}
	}
	permissions := make(map[string]string, len(permRaw))
	for k, val := range permRaw {
		s, ok := val.(string)
		if !ok {
			return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: permissions value for %q is not string", k)}
		}
		permissions[k] = s
	}

	// 4. repositories の取得（省略可）
	// キーが存在しない → undefined、キーが存在する → defined（[] または [...] ）
	_, _, scopeHasRepo := strings.Cut(scope, "/")
	repoVal, reposExists := p["repositories"]

	// scope=org/repo のとき repositories は undefined でなければならない（CLAUDE.md 仕様）
	if scopeHasRepo && reposExists {
		return nil, nil, &policyerrors.DenialError{Reason: "policy: repositories must be undefined when scope is org/repo"}
	}

	var repositories []string
	if !reposExists {
		// undefined → scope から自動導出
		repositories = defaultRepositories(scope)
	} else {
		rawRepos, ok := repoVal.([]interface{})
		if !ok {
			return nil, nil, &policyerrors.DenialError{Reason: fmt.Sprintf("policy: repositories has unexpected type %T", repoVal)}
		}
		if len(rawRepos) == 0 {
			// [] → nil（GitHub API で repositories を omit → App の全リポジトリ）
			repositories = nil
		} else {
			repositories = make([]string, 0, len(rawRepos))
			for _, r := range rawRepos {
				s, ok := r.(string)
				if !ok {
					return nil, nil, &policyerrors.DenialError{Reason: "policy: repositories contains non-string value"}
				}
				repositories = append(repositories, s)
			}
		}
	}

	return permissions, repositories, nil
}

// defaultRepositories returns the default repository list for a given scope
// when the policy does not define repositories.
//
//	scope="org/repo" → ["org/repo"]
//	scope="org"      → ["org/.github"]
func defaultRepositories(scope string) []string {
	_, _, hasRepo := strings.Cut(scope, "/")
	if hasRepo {
		return []string{scope}
	}
	return []string{scope + "/.github"}
}
```

### 修正 1-B: `pkg/policyerrors/errors.go` を新規作成する

```go
package policyerrors

// DenialError はポリシー起因の失敗を表す。
// server.go はこのエラーを受け取った場合 403 FORBIDDEN を返す（fail-closed 方針）。
// 内部エラー（INTERNAL_ERROR）と区別するために独立した型として定義する。
type DenialError struct {
	Reason string
}

func (e *DenialError) Error() string {
	return e.Reason
}
```

**なぜ `pkg/verifier` ではなく独立した `pkg/policyerrors` に置くか:**

Go のインターフェースは implicit satisfaction であり、カスタム Verifier 実装者は
`pkg/verifier` を import せずともインターフェースを満たせる。
`DenialError` を `pkg/verifier` に置くと、fail-closed 挙動を実装したいカスタム実装者が
エラー型のためだけに `pkg/verifier` を import しなければならなくなる。
さらに一度 `pkg/verifier` に置いた型を別パッケージに移すことは OSS ライブラリとして破壊的変更になる。

そのため、`DenialError` は最初から独立した薄いパッケージ `pkg/policyerrors` に置き、
`pkg/verifier`・`pkg/server` ともにこれを import する設計とする。

### 修正 1-C: `.github/mini-gh-sts/` のテスト用ポリシーファイルを更新する

Issue 1-A の変更により、フレームワークが `issuer` ルールを評価して `input.iss` と照合するようになる。
既存の 3 ファイルはすべて `issuer` ルールと `permissions` ルールが欠けており、
`allow` ブロック内で `input.iss == "..."` を直接チェックしている。
修正後はこれらのファイルはポリシーエラー（`DenialError`）になってトークンが発行できなくなる。

**修正方針:**
- `issuer := "https://token.actions.githubusercontent.com"` を追加する
- `permissions := {...}` を追加する（**各ポリシーに適切な権限を設定すること**）
- `allow` ブロック内の `input.iss == "..."` チェックを削除する（フレームワークが担うため）

**修正例（test-policy-1.rego）:**

変更前:
```rego
package mini_gh_sts

default allow := false

allow if {
	input.iss == "https://token.actions.githubusercontent.com"
	regex.match(`^repo:yagihash/mini-gh-sts:.+$`, input.sub)
}
```

変更後:
```rego
package mini_gh_sts

issuer := "https://token.actions.githubusercontent.com"

permissions := {"contents": "read"}  # 実際に必要な権限に変更すること

default allow := false

allow if {
	regex.match(`^repo:yagihash/mini-gh-sts:.+$`, input.sub)
}
```

**test-policy-2.rego・test-policy-3.rego も同様のパターンで修正すること。**
`permissions` の具体的な値はポリシーの用途に合わせて設定すること（この計画では `{"contents": "read"}` を仮置きしているが、実際の権限要件を確認した上で設定すること）。

### 修正 1-D: `pkg/server/server.go` のエラー判定を修正する

`handleToken()` の以下の箇所を修正する（現在 168〜176 行目付近）:

また `pkg/server/server.go` の `policyVerifier` ローカルインターフェースも合わせて変更する:

```go
type policyVerifier interface {
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}
```

**変更前:**
```go
allowed, permissions, repositories, err := s.policyVerifier.Verify(r.Context(), claims.Raw, req.Scope, req.Policy)
if err != nil {
	s.logger.ErrorContext(r.Context(), "policy evaluation failed", "error", err)
	writeError(w, http.StatusInternalServerError, "policy evaluation failed", "INTERNAL_ERROR")
	return
}
if !allowed {
	s.logger.WarnContext(r.Context(), "policy denied token issuance", "scope", req.Scope, "policy", req.Policy)
	writeError(w, http.StatusForbidden, "token issuance denied by policy", "FORBIDDEN")
	return
}
```

**変更後:**
```go
permissions, repositories, err := s.policyVerifier.Verify(r.Context(), claims.Raw, req.Scope, req.Policy)
if err != nil {
	var policyErr *policyerrors.DenialError
	if errors.As(err, &policyErr) {
		s.logger.WarnContext(r.Context(), "policy denied token issuance", "scope", req.Scope, "policy", req.Policy, "reason", policyErr.Reason)
		writeError(w, http.StatusForbidden, "token issuance denied by policy", "FORBIDDEN")
	} else {
		s.logger.ErrorContext(r.Context(), "policy evaluation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "policy evaluation failed", "INTERNAL_ERROR")
	}
	return
}
```

`server.go` の import に以下を追加する:
```go
"errors"
"github.com/yagihash/mini-gh-sts/pkg/policyerrors"
```

---

## Issue 2（P1）: CLAUDE.md の記述を実装と一致させる

### 問題

CLAUDE.md の「App API」セクションが実際の実装と異なる:

| 項目 | CLAUDE.md の記述 | 実際の実装 |
|---|---|---|
| パッケージ | `pkg/app` | `pkg/server` |
| 型名 | `App` | `Server` |
| コンストラクタ | `app.New(appID, logger, signer, verifier)` | `server.New(addr, log, ov, ti, pv)` |
| メソッド | `app.Serve(addr)` | `srv.Start()` / `srv.Shutdown(ctx)` |

### 修正 2-A: CLAUDE.md の「パッケージ責務」表を修正する

`pkg/app` の行を削除し、以下に差し替える:

```markdown
| `pkg/server` | HTTP ハンドラ・エンドポイントルーティング・ロギングミドルウェア。各コンポーネント（oidcVerifier・tokenIssuer・policyVerifier）を受け取って束ねる HTTP サーバー。 |
```

### 修正 2-B: CLAUDE.md の「App API」セクションを書き換える

セクション名を「Server API」に変更し、内容を以下に差し替える:

```markdown
## Server API

\`\`\`go
srv := server.New(addr, logger, oidcVerifier, tokenIssuer, policyVerifier)
srv.Start()
srv.Shutdown(ctx)
\`\`\`

`Server` は HTTP サーバー・ロギングミドルウェア・エンドポイントルーティングを担う。
各コンポーネント（oidcVerifier・tokenIssuer・policyVerifier）は `cmd/mini-gh-sts/main.go` が構築して注入する。
```

### 修正 2-C: CLAUDE.md の「依存関係」図を修正する

`App` を `Server` に差し替える:

```markdown
## 依存関係

\`\`\`
Server
  ├─ pkg/oidc       （OIDC JWT 検証 → Claims 取得、コア）
  ├─ pkg/verifier   （Claims + scope + policy → 発行可否・permissions・repositories）
  │     └─ pkg/policystore  （Rego ファイル取得、Verifier の内部依存）
  └─ pkg/githubapp  （GitHub App Installation Access Token 発行）
\`\`\`
```

---

## Issue 3（P2）: `KMSSigner.SignRS256()` が context を無視している

### 問題

`pkg/signer/kms.go:28` で `context.Background()` をハードコードしているため、
HTTP リクエストのキャンセル・タイムアウトが KMS 呼び出しに伝搬されない。

`signer.Signer` インターフェースが `context.Context` を受け取らない設計のため。

### 修正 3-A: `pkg/signer/signer.go` のインターフェースを変更する

```go
package signer

import "context"

type Signer interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}
```

### 修正 3-B: `pkg/signer/kms.go` の実装を更新する

`SignRS256` のシグネチャと本体を変更する:

```go
func (s *KMSSigner) SignRS256(ctx context.Context, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: h[:],
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("kms asymmetric sign: %w", err)
	}
	return resp.Signature, nil
}
```

import に `"context"` を追加する（`"context"` は既存の import にない場合のみ）。

### 修正 3-C: `internal/signer/rsa.go` の実装を更新する

`SignRS256` のシグネチャを変更する（本体ロジックは変わらない）:

```go
import "context"

func (s *RSASigner) SignRS256(_ context.Context, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, h[:])
}
```

### 修正 3-D: `pkg/githubapp/token.go` を更新する

`jwtSigner` ローカルインターフェースを変更する:

```go
type jwtSigner interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}
```

`signJWT()` のシグネチャを `ctx` を受け取るよう変更する:

```go
func (t *TokenIssuer) signJWT(ctx context.Context) (string, error) {
	// ...（既存のヘッダ・ペイロード生成ロジックはそのまま）
	sig, err := t.signer.SignRS256(ctx, []byte(signingInput))
	// ...
}
```

`Issue()` の `signJWT()` 呼び出しを変更する:

```go
jwt, err := t.signJWT(ctx)
```

import に `"context"` を追加する。

### 修正 3-E: `pkg/policystore/appclient.go` を更新する

`jwtSigner` ローカルインターフェースを変更する:

```go
type jwtSigner interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}
```

`jwt()` メソッドを `signJWT(ctx context.Context)` に**リネームしつつ** ctx を受け取るよう変更する
（`pkg/githubapp/token.go` の `signJWT` に名前を統一する）:

```go
func (c *appClient) signJWT(ctx context.Context) (string, error) {
	// ...（既存のヘッダ・ペイロード生成ロジックはそのまま）
	sig, err := c.signer.SignRS256(ctx, []byte(signingInput))
	// ...
}
```

`GetFileContent()` 内の呼び出しを変更する:

```go
jwt, err := c.signJWT(ctx)
```

import に `"context"` を追加する。

---

## Issue 4（P2）: linter の実装

### 問題

CLAUDE.md に記載されている `mini-gh-sts-lint` バイナリが未実装（`cmd/mini-gh-sts-lint/` が存在しない）。

### 修正 4-A: `cmd/mini-gh-sts-lint/main.go` を新規作成する

**CLI 仕様:**

```
mini-gh-sts-lint [--scope <scope>] <policy.rego> [<policy.rego> ...]

  --scope <scope>    org/repo または org 形式。指定した場合のみ scope 制約を検証する。
                     org/repo を指定した場合、repositories が defined なら error。
```

**検証内容（全ファイルに適用）:**
1. `data.mini_gh_sts.issuer` が文字列として定義されているか
2. `data.mini_gh_sts.allow` が定義されているか
3. `data.mini_gh_sts.permissions` が定義されているか
4. `permissions` のキー・値が GitHub App の有効な権限名か（後述）
5. `--scope org/repo` が指定された場合: `data.mini_gh_sts.repositories` が defined なら error

**有効な GitHub App 権限名（キー）と有効な値:**
- キー: GitHub App の権限名（`contents`, `issues`, `pull_requests`, `actions`, `checks`, `deployments`, `environments`, `metadata`, `packages`, `pages`, `repository_projects`, `secret_scanning_alerts`, `security_events`, `statuses`, `vulnerability_alerts`, `workflows` 等）
- 値: `"read"` または `"write"`
- 正確なリストは https://docs.github.com/en/rest/apps/apps の権限仕様に従う

**exit code:**
- 0: 問題なし
- 1: 検証エラーあり（エラー内容を stderr に出力）

**実装方針:**
- OPA SDK (`github.com/open-policy-agent/opa/v1/rego`) を使って各ルールを評価する
- ダミーの `input`（空 map）を渡して静的に評価する
- `--scope` は `flag` パッケージで実装する

### 修正 4-B: `.github/actions/lint/action.yml` を新規作成する

```yaml
name: mini-gh-sts-lint
description: Lint Rego policy files for mini-gh-sts
inputs:
  files:
    description: 'Space-separated list of .rego files to lint'
    required: true
  scope:
    description: 'Scope (org or org/repo) for scope-specific validation'
    required: false
    default: ''
runs:
  using: composite
  steps:
    - name: Run mini-gh-sts-lint
      shell: bash
      run: |
        # ビルドしてから実行する（CI 環境では Go がインストール済みを前提とする）
        go run ./cmd/mini-gh-sts-lint/... \
          ${{ inputs.scope != '' && format('--scope {0}', inputs.scope) || '' }} \
          ${{ inputs.files }}
```

---

## Issue 5（P2）: テストの追加

### 修正 5-A: `pkg/verifier/rego_test.go` を新規作成する

以下のテストケースをすべて実装すること。
PolicyStore のモック実装を同ファイル内に定義する:

```go
type staticPolicyStore struct {
	content []byte
	err     error
}

func (s *staticPolicyStore) Fetch(_ context.Context, _, _ string) ([]byte, error) {
	return s.content, s.err
}
```

**テストケース一覧:**

| テスト名 | 入力ポリシー | 期待する戻り値 |
|---|---|---|
| `TestVerify_IssuerUndefined` | `issuer` ルールなし | `policyerrors.DenialError` |
| `TestVerify_IssuerMismatch` | `issuer := "https://a.example"` + `iss` クレームが別値 | `policyerrors.DenialError` |
| `TestVerify_AllowUndefined` | issuer 一致 + `allow` ルールなし | `policyerrors.DenialError` |
| `TestVerify_AllowFalse` | issuer 一致 + `allow := false` | `policyerrors.DenialError` |
| `TestVerify_PermissionsUndefined` | issuer 一致 + allow true + `permissions` なし | `policyerrors.DenialError` |
| `TestVerify_Success_ReposUndefined_OrgRepo` | 正常ポリシー + repos undefined + scope=`org/repo` | `permissions 返却, repos=["org/repo"], err=nil` |
| `TestVerify_Success_ReposUndefined_OrgOnly` | 正常ポリシー + repos undefined + scope=`org` | `permissions 返却, repos=["org/.github"], err=nil` |
| `TestVerify_Success_ReposEmpty` | 正常ポリシー + `repositories := []` + scope=`org` | `permissions 返却, repos=nil, err=nil` |
| `TestVerify_Success_ReposList` | 正常ポリシー + `repositories := ["org/a"]` + scope=`org` | `permissions 返却, repos=["org/a"], err=nil` |
| `TestVerify_ReposDefinedWithOrgRepoScope` | 正常ポリシー + `repositories := ["org/a"]` + scope=`org/repo` | `policyerrors.DenialError` |
| `TestVerify_PolicyFetchError` | store が error を返す | `policyerrors.DenialError` |
| `TestVerify_RegoBadSyntax` | Rego 構文エラーのポリシー | `policyerrors.DenialError` |

### 修正 5-B: `pkg/app/handler_test.go` を新規作成する

`package app`（ホワイトボックステスト）として実装する。
`newServer()` に mock を直接 inject することで、ID Token の準備が不要になる。
各 mock を同ファイル内に定義する:

```go
// oidcVerifier mock: 常に固定の Claims を返す（本物の JWT 検証をスキップ）
type mockOIDCVerifier struct {
    claims minioidc.Claims
    err    error
}
func (m *mockOIDCVerifier) Verify(_ context.Context, _ string) (minioidc.Claims, error) {
    return m.claims, m.err
}

// tokenIssuer mock
type mockTokenIssuer struct {
    result githubapp.IssueResult
    err    error
}
func (m *mockTokenIssuer) Issue(_ context.Context, _ string, _ map[string]string, _ []string) (githubapp.IssueResult, error) {
    return m.result, m.err
}

// policyVerifier mock
type mockPolicyVerifier struct {
    permissions map[string]string
    repos       []string
    err         error
}
func (m *mockPolicyVerifier) Verify(_ context.Context, _ map[string]interface{}, _, _ string) (map[string]string, []string, error) {
    return m.permissions, m.repos, m.err
}
```

`httptest.NewRecorder` でレスポンスをキャプチャする。

**テストケース一覧:**

| テスト名 | 状況 | 期待する HTTP レスポンス |
|---|---|---|
| `TestHandleHealthz` | GET /healthz | 200 + `{}` |
| `TestHandleToken_MissingContentType` | Content-Type なし | 415 + `UNSUPPORTED_MEDIA_TYPE` |
| `TestHandleToken_MissingAuthorization` | Authorization ヘッダなし | 400 + `BAD_REQUEST` |
| `TestHandleToken_MissingScope` | scope が空 | 400 + `MISSING_SCOPE` |
| `TestHandleToken_MissingPolicy` | policy が空 | 400 + `MISSING_POLICY` |
| `TestHandleToken_InvalidOIDCToken` | oidcVerifier がエラー | 401 + `INVALID_TOKEN` |
| `TestHandleToken_PolicyDenialError` | policyVerifier が `policyerrors.DenialError` を返す | 403 + `FORBIDDEN` |
| `TestHandleToken_PolicyInternalError` | policyVerifier が通常 error を返す | 500 + `INTERNAL_ERROR` |
| `TestHandleToken_TokenIssueError` | tokenIssuer がエラー | 500 + `INTERNAL_ERROR` |
| `TestHandleToken_Success` | 全コンポーネントが正常 | 200 + token/expires_at/permissions/repositories |

---

## Issue 6（P2）: ログ設計の整理

### 背景

現在 `pkg/server/server.go` と `pkg/logger/` にロギング実装があるが、
以下の観点で設計を見直す必要があるかどうか未検討:

- deny 理由（issuer 不一致 / allow=false / policyerrors.DenialError）がログに残っているか
- `policyerrors.DenialError` の `Reason` フィールドが warn ログに含まれているか（Issue 1-C で追加済み）
- 正常発行時に scope・policy・permissions・repositories がログに残っているか
- request_id との紐付けが一貫しているか

### 方針

**既存のロギング実装は別途分析してから対応する。**
このイシューは現時点では「調査 → 設計 → 実装」の 3 ステップが必要なため、
実装計画に含める前に以下を確認すること:

1. `pkg/server/server.go` の各ハンドラで何をどのレベル（Debug/Info/Warn/Error）でログしているか
2. `pkg/logger/logger.go` と `pkg/logger/cloudlogging/cloudlogging.go` の実装を読み、
   structured logging のキー設計が一貫しているか確認する
3. 上記の分析結果をもとに、追加・変更すべきログを具体化した上でこのセクションを更新すること

### 暫定合意事項

- `issuer` 不一致は `allow=false` と同じ扱い（`policyerrors.DenialError` ではなく `(false, nil, nil, nil)`）
- deny 時は server.go が一律 Warn ログを出す（Issue 1-C の実装で対応済み）
- ログの詳細設計は既存実装の分析後に確定させる

---

## Issue 7（P1）: `pkg/app` の新設

### 決定事項

`pkg/app` パッケージを新設し、`App` 型を定義する（方針 B）。
`main.go` は「どの実装を選ぶか」だけを知り、コンポーネントの内部ワイヤリングを一切含まない。

**責務の切り分け:**

| コード | 配置 | 理由 |
|---|---|---|
| `pkg/oidc.New(hostname)` | `pkg/app` の内部 | App の実装詳細、プラガブルでない |
| `pkg/githubapp.New(appID, signer)` | `pkg/app` の内部 | App の実装詳細、プラガブルでない |
| `pkg/server.New(...)` | `pkg/app` の内部 | App の実装詳細 |
| `pkg/signer.NewKMSSigner(...)` | `main.go` | プラガブル（KMS vs RSA を選ぶ） |
| `pkg/policystore.NewRepoPolicyStore(...)` | `main.go` | プラガブル（Verifier に渡すための構築） |
| `pkg/verifier.New(ps)` | `main.go` | プラガブル（カスタム Verifier の差し替え境界） |

### 修正 7-A: `pkg/app/app.go` を新規作成する

```go
package app

import (
	"context"
	"errors"
	"time"

	"github.com/yagihash/mini-gh-sts/pkg/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

// Config は App の設定を保持する。
// AppID・Hostname・Logger・Signer・Verifier は必須フィールド。
// タイムアウト系はゼロ値の場合にデフォルト値が使われる。
type Config struct {
	AppID    string
	Hostname string
	Logger   logger.Logger
	Signer   signer.Signer
	Verifier verifier.Verifier

	// オプション（ゼロ値の場合は以下のデフォルト値を使う）
	// ReadHeaderTimeout: 5s, ReadTimeout: 10s, WriteTimeout: 30s, IdleTimeout: 120s
	// MaxRequestBodyBytes: 1 MiB
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
}

// Validate は必須フィールドを検証し、複数の不足があれば errors.Join で束ねて返す。
func (c Config) Validate() error {
	var errs []error
	if c.AppID == "" {
		errs = append(errs, errors.New("AppID is required"))
	}
	if c.Hostname == "" {
		errs = append(errs, errors.New("Hostname is required"))
	}
	if c.Logger == nil {
		errs = append(errs, errors.New("Logger is required"))
	}
	if c.Signer == nil {
		errs = append(errs, errors.New("Signer is required"))
	}
	if c.Verifier == nil {
		errs = append(errs, errors.New("Verifier is required"))
	}
	return errors.Join(errs...)
}

type App struct {
	srv *server.Server
}

// New は Config を検証し、mini-gh-sts サービスを構築する。
// 必須フィールドが欠けている場合は error を返す。
func New(cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ov := minioidc.New(cfg.Hostname)
	ti := githubapp.New(cfg.AppID, cfg.Signer)
	// newServer は pkg/app/server.go に定義する unexported 関数
	srv := newServer(cfg.Logger, ov, ti, cfg.Verifier, cfg)
	return &App{srv: srv}, nil
}

func (a *App) Serve(addr string) error {
	return a.srv.Start(addr)
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
```

**`pkg/server/` は削除して `pkg/app/` に統合する:**

`pkg/server/server.go` の HTTP サーバー・ミドルウェア・ハンドラのロジックを
`pkg/app/` パッケージ内の複数ファイルに移動する。
外部から見える型・関数は `pkg/app` のみとなり、HTTP サーバー層は隠蔽される。

```
pkg/app/
  app.go      - App 型・Config・Validate・New・Serve・Shutdown（公開 API）
  server.go   - HTTP サーバー構築・ミドルウェア・responseWriter（unexported）
  handler.go  - handleToken・handleHealthz・writeError（unexported）
```

タイムアウトのデフォルト値は `server.go` 内に定数として定義し、
`Config` のゼロ値フィールドに対して適用する。

### 修正 7-B: `cmd/mini-gh-sts/main.go` を書き換える

`pkg/oidc`・`pkg/githubapp`・`pkg/server` の import を削除し、
`pkg/app` を使う形に変更する:

```go
package main

import (
	"context"
	// ... (config, logger, signal handling)
	"github.com/yagihash/mini-gh-sts/pkg/app"
	"github.com/yagihash/mini-gh-sts/pkg/policystore"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

func realMain() int {
	cfg, err := config.Load()
	// ...

	log := logger.New(cfg.Debug)

	kmsSigner, err := signer.NewKMSSigner(ctx, cfg.KMSKeyName())
	// ...

	ps := policystore.NewRepoPolicyStore(cfg.AppID, kmsSigner)
	pv := verifier.New(ps)

	a, err := app.New(app.Config{
		AppID:    cfg.AppID,
		Hostname: cfg.Hostname,
		Logger:   log,
		Signer:   kmsSigner,
		Verifier: pv,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize app: %v\n", err)
		return 1
	}

	// シグナルハンドリング・graceful shutdown は従来通り
	// ...

	addr := net.JoinHostPort("", strconv.Itoa(cfg.Port))
	if err := a.Serve(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.ErrorContext(ctx, "server error", "error", err)
		return 1
	}
	return 0
}
```

### Issue 2 との関係

Issue 2（CLAUDE.md の修正）は本 Issue の実装完了後に行う。
CLAUDE.md の「App API」セクションを以下に更新する:

```markdown
## App API

\`\`\`go
a, err := app.New(app.Config{
    AppID:    appID,
    Hostname: hostname,
    Logger:   logger,
    Signer:   signer,
    Verifier: verifier,
    // タイムアウト系は省略可（ゼロ値でデフォルト値が使われる）
})
a.Serve(addr)
a.Shutdown(ctx)
\`\`\`

`App` は「mini-gh-sts サービス」そのものを表す型。
OIDC 検証・GitHub App Token 発行・HTTP サーバーを内部で構築して束ねる。
`Signer` と `Verifier`（+`PolicyStore`）はプラガブルであり、呼び出し元が実装を選択して渡す。
```
