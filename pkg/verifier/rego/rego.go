package rego

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	oparego "github.com/open-policy-agent/opa/v1/rego"
	"github.com/yagihash/ghmint/pkg/policystore"
	"github.com/yagihash/ghmint/pkg/verifier"
)

const evalTimeout = 5 * time.Second

// allowedBuiltins is the set of OPA built-in functions that policies may use.
// Side-effectful built-ins (http.send, net.lookup_ip_addr, opa.runtime, etc.) are intentionally omitted.
var allowedBuiltins = map[string]bool{
	// Comparison
	"eq": true, "neq": true, "lt": true, "gt": true, "lte": true, "gte": true,
	// Arithmetic
	"plus": true, "minus": true, "mul": true, "div": true, "rem": true,
	"abs": true, "ceil": true, "floor": true, "round": true, "numbers.range": true,
	// Aggregates
	"count": true, "sum": true, "product": true, "max": true, "min": true,
	"all": true, "any": true, "sort": true,
	// String
	"concat": true, "contains": true, "endswith": true, "startswith": true,
	"lower": true, "upper": true, "split": true, "trim": true,
	"trim_left": true, "trim_right": true, "trim_prefix": true, "trim_suffix": true,
	"replace": true, "indexof": true, "indexof_n": true,
	"substring": true, "format_int": true, "sprintf": true,
	"strings.count": true, "strings.replace_n": true, "strings.reverse": true,
	"strings.any_prefix_match": true, "strings.any_suffix_match": true,
	// Regex / Glob
	"regex.match": true, "regex.is_valid": true, "regex.split": true,
	"regex.find_n": true, "regex.replace": true, "regex.template_match": true,
	"glob.match": true, "glob.quote_meta": true,
	// Array / Set / Object
	"array.concat": true, "array.slice": true, "array.reverse": true,
	"intersection": true, "union": true, "difference": true,
	"object.get": true, "object.keys": true, "object.values": true,
	"object.union": true, "object.union_n": true,
	"object.remove": true, "object.filter": true, "object.subset": true,
	// JSON / Encoding
	"json.marshal": true, "json.unmarshal": true, "json.is_valid": true,
	"json.filter": true, "json.remove": true,
	"base64.encode": true, "base64.decode": true,
	"base64url.encode": true, "base64url.decode": true,
	// Types
	"is_number": true, "is_string": true, "is_boolean": true,
	"is_array": true, "is_set": true, "is_object": true, "is_null": true,
	"type_name": true,
	// Time (read-only)
	"time.now_ns": true, "time.parse_rfc3339_ns": true, "time.parse_ns": true,
	"time.format": true, "time.date": true, "time.clock": true,
	"time.weekday": true, "time.add_date": true, "time.diff": true,
	// OPA internals required for evaluation
	"assign": true, "unify": true, "equal": true, "internal.print": true,
}

func safeCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	safe := caps.Builtins[:0]
	for _, b := range caps.Builtins {
		if allowedBuiltins[b.Name] {
			safe = append(safe, b)
		}
	}
	caps.Builtins = safe
	return caps
}

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
		oparego.Capabilities(safeCapabilities()),
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
