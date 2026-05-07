package rego

import (
	"context"
	"fmt"
	"strings"
	"time"

	oparego "github.com/open-policy-agent/opa/v1/rego"
	"github.com/yagihash/ghmint/internal/regocaps"
	"github.com/yagihash/ghmint/pkg/policystore"
	"github.com/yagihash/ghmint/pkg/verifier"
)

const evalTimeout = 5 * time.Second

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
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("fetch policy: %v", err)}
	}

	evalCtx, cancel := context.WithTimeout(ctx, evalTimeout)
	defer cancel()

	// Query data.ghmint as a whole so that undefined rules are absent from the map,
	// allowing correct distinction between undefined and defined-empty repositories.
	rs, err := oparego.New(
		oparego.Query("data.ghmint"),
		oparego.Module("policy.rego", string(content)),
		oparego.Input(claims),
		oparego.Capabilities(regocaps.SafeCapabilities()),
	).Eval(evalCtx)
	if err != nil {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("evaluate policy: %v", err)}
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil, &verifier.DenialError{Reason: "policy: data.ghmint is undefined (check package declaration)"}
	}
	p, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: data.ghmint has unexpected type %T", rs[0].Expressions[0].Value)}
	}

	issuerVal, issuerExists := p["issuer"]
	if !issuerExists {
		return nil, nil, &verifier.DenialError{Reason: "policy: issuer is undefined"}
	}
	issuer, ok := issuerVal.(string)
	if !ok {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: issuer has unexpected type %T", issuerVal)}
	}
	claimIss, _ := claims["iss"].(string)
	if claimIss != issuer {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: issuer mismatch (expected: %s, got: %s)", issuer, claimIss)}
	}

	allowVal, allowExists := p["allow"]
	if !allowExists {
		return nil, nil, &verifier.DenialError{Reason: "policy: allow is undefined"}
	}
	allow, isBool := allowVal.(bool)
	if !isBool {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: allow has unexpected type %T", allowVal)}
	}
	if !allow {
		return nil, nil, &verifier.DenialError{Reason: "policy: allow is false"}
	}

	permVal, permExists := p["permissions"]
	if !permExists {
		return nil, nil, &verifier.DenialError{Reason: "policy: permissions is undefined"}
	}
	permRaw, ok := permVal.(map[string]interface{})
	if !ok {
		return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: permissions has unexpected type %T", permVal)}
	}
	permissions := make(map[string]string, len(permRaw))
	for k, val := range permRaw {
		s, ok := val.(string)
		if !ok {
			return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: permissions value for %q is not string", k)}
		}
		permissions[k] = s
	}

	_, _, scopeHasRepo := strings.Cut(scope, "/")
	repoVal, reposExists := p["repositories"]

	if scopeHasRepo && reposExists {
		return nil, nil, &verifier.DenialError{Reason: "policy: repositories must be undefined when scope is org/repo"}
	}

	var repositories []string
	if !reposExists {
		repositories = defaultRepositories(scope)
	} else {
		rawRepos, ok := repoVal.([]interface{})
		if !ok {
			return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: repositories has unexpected type %T", repoVal)}
		}
		if len(rawRepos) == 0 {
			repositories = nil
		} else {
			repositories = make([]string, 0, len(rawRepos))
			for _, r := range rawRepos {
				s, ok := r.(string)
				if !ok {
					return nil, nil, &verifier.DenialError{Reason: "policy: repositories contains non-string value"}
				}
				org, name, found := strings.Cut(s, "/")
				if !found || org == "" || name == "" {
					return nil, nil, &verifier.DenialError{Reason: fmt.Sprintf("policy: repository %q is not in owner/repo format", s)}
				}
				repositories = append(repositories, s)
			}
		}
	}

	return permissions, repositories, nil
}

// defaultRepositories returns the default repository for a given scope when the policy omits repositories.
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
