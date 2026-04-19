package verifier

import "context"

// DenialError represents a policy-driven rejection.
// The server returns 403 when it receives this error (fail-closed policy).
type DenialError struct {
	Reason string
}

func (e *DenialError) Error() string {
	return e.Reason
}

type Verifier interface {
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}
