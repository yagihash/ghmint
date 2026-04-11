package policystore

import "context"

type PolicyStore interface {
	Fetch(ctx context.Context, scope string, policy string) ([]byte, error)
}
