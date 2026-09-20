package policystore

import (
	"context"
	"errors"
)

type PolicyStore interface {
	Fetch(ctx context.Context, scope string, policy string) ([]byte, error)
}

// ErrUpstream marks a Fetch failure as caused by the backing store's
// upstream service (e.g. a GitHub outage or network failure) rather than
// the policy itself (missing file, bad name, etc.). Implementations should
// wrap errors with it (fmt.Errorf("...: %w", ErrUpstream)) so callers can
// distinguish infrastructure failures from policy-driven denials via
// errors.Is, without changing the fail-closed HTTP response.
var ErrUpstream = errors.New("policy store upstream error")
