package signer

type Signer interface {
	SignRS256([]byte) ([]byte, error)
}
