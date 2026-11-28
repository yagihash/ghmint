package verifier

import "context"

// DenialError represents a policy-driven rejection.
// The server returns 403 when it receives this error (fail-closed policy).
type DenialError struct {
	Reason string
	// Upstream is true when the denial was caused by a policy store /
	// GitHub infrastructure failure (e.g. an outage or network error)
	// rather than the policy content itself. The response to the client
	// is still 403 per the fail-closed policy (see CLAUDE.md), but callers
	// may log or alert on this separately from a genuine policy denial.
	Upstream bool
}

func (e *DenialError) Error() string {
	return e.Reason
}

// DefaultApp is the name of the GitHub App used when a policy does not select
// one with the "app" rule. It is also the App that fetches policy files and
// receives webhooks.
const DefaultApp = "default"

// Result is the outcome of a successful policy evaluation.
type Result struct {
	Permissions  map[string]string
	Repositories []string
	// App is the name of the GitHub App the token must be issued from.
	// It is DefaultApp when the policy omits the "app" rule. Whether the name
	// is actually registered is checked by the caller.
	App string
}

type Verifier interface {
	Verify(ctx context.Context, claims map[string]any, scope, policy string) (Result, error)
}
