package regocaps_test

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/yagihash/ghmint/internal/regocaps"
)

func TestSafeCapabilities_InOperator(t *testing.T) {
	tests := map[string]string{
		"member_2": `package ghmint
allow if input.ref in {"refs/heads/main", "refs/heads/dev"}
`,
		"member_3": `package ghmint
allow if {
	some k, v in input.labels
	k == "a"
	v == "b"
}
`,
	}
	input := map[string]any{
		"ref":    "refs/heads/main",
		"labels": map[string]any{"a": "b"},
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			rs, err := rego.New(
				rego.Query("data.ghmint.allow"),
				rego.Module("policy.rego", mod),
				rego.Input(input),
				rego.Capabilities(regocaps.SafeCapabilities()),
			).Eval(context.Background())
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if !rs.Allowed() {
				t.Fatalf("expected allow, got %v", rs)
			}
		})
	}
}
