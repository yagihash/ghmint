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
