package verifier

import "context"

type Verifier interface {
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (ok bool, permissions map[string]string, repositories []string, err error)
}
