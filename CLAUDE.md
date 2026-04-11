# mini-gh-sts アーキテクチャガイド

## 概要

GitHub Actions の OIDC ID Token を受け取り、Rego ポリシーで検証した上で GitHub App Installation Token を発行する STS (Security Token Service)。

## パッケージ責務

| パッケージ | 責務 |
|---|---|
| `pkg/signer` | RS256 JWT 署名（`SignRS256([]byte) ([]byte, error)`） |
| `pkg/oidc` | OIDC JWT 検証（署名・aud・exp・iat） |
| `pkg/verifier` | 検証済み Claims をポリシーに照らして発行可否を判断 |
| `pkg/policystore` | Rego ファイルの取得（Verifier の内部依存） |
| `pkg/githubapp` | GitHub App Installation Token の発行 |
| `pkg/server` | HTTP ハンドラ・OIDC 検証の呼び出し・各コンポーネントの組み合わせ |

## Verifier の責務と境界

`pkg/verifier/Verifier` の責務は **検証済み OIDC Claims を Rego ポリシーに照らして発行可否を判断すること** のみ。

- JWT 署名検証・aud・exp・iat の検証は **server の責務**（`pkg/oidc` を使う）
- `PolicyStore` は Verifier の **内部依存**。server は PolicyStore を直接知らない。

```
server
  ├─ pkg/oidc  （OIDC JWT 検証 → Claims 取得）
  ├─ pkg/verifier  （Claims + scope + policy → 発行可否）
  │     └─ pkg/policystore  （Rego ファイル取得、Verifier の内部依存）
  └─ pkg/githubapp  （GitHub App トークン発行）
```

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

### Rego ポリシー

- パッケージ名: `mini_gh_sts`
- 評価クエリ: `data.mini_gh_sts.allow`
- `input` には ID Token の全クレームが渡される（`sub`, `repository`, `ref`, `workflow` 等）

## 目標とするサーバー API

```go
// 現状
server.New(addr, logger, oidcVerifier, tokenIssuer)

// 将来の目標（段階的に移行）
server.New(logger, signer, verifier)           // 3 arg 版
server.New(logger, signer, verifier, policystore)  // 4 arg 版（policystore を外から渡す場合）
```

- `signer` = `pkg/signer/Signer`（RS256 JWT 署名）
- `verifier` = `pkg/verifier/Verifier` 実装
- `policystore` = `pkg/policystore/PolicyStore` 実装（Verifier 内部依存が基本）
