package policystore

type PolicyStore interface {
	Fetch(scope string, policy string) ([]byte, error)
}
