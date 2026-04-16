package signer

import "context"

type Signer interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}
