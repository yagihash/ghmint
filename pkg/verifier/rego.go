package verifier

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
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

func (v *RegoVerifier) Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (bool, map[string]string, []string, error) {
	content, err := v.store.Fetch(ctx, scope, policy)
	if err != nil {
		return false, nil, nil, fmt.Errorf("fetch policy: %w", err)
	}

	r := rego.New(
		rego.Query("data.mini_gh_sts.allow"),
		rego.Module("policy.rego", string(content)),
		rego.Input(claims),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return false, nil, nil, fmt.Errorf("evaluate policy: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, nil, nil, nil
	}

	allow, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil, nil, fmt.Errorf("unexpected policy result type: %T", rs[0].Expressions[0].Value)
	}

	return allow, nil, nil, nil
}
