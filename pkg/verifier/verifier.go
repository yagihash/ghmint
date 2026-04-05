package verifier

type Verifier interface {
	Verify(scope string, policy string) (ok bool, permissions map[string]string, repositories []string)
}
