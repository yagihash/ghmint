package github

import (
	"strings"
	"testing"
)

// FuzzValidators exercises the scope/policy regexes and the ".." guard.
// Any input that passes the validators must not contain shell-metacharacters
// or path-traversal sequences that could affect URL path construction.
func FuzzValidators(f *testing.F) {
	seeds := []struct{ scope, policy string }{
		{"", ""},
		{"owner", "p"},
		{"owner/repo", "p"},
		{"..", "p"},
		{"owner/..", "p"},
		{"own..er", "p"},
		{"owner", ".."},
		{"owner", "p/x"},
		{"owner/repo/extra", "p"},
		{"own er", "p"},
		{"owner", "p p"},
		{"owner", "p\x00"},
		{"owner\n", "p"},
	}
	for _, s := range seeds {
		f.Add(s.scope, s.policy)
	}

	f.Fuzz(func(t *testing.T, scope, policy string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("validators panicked on scope=%q policy=%q: %v", scope, policy, r)
			}
		}()

		scopeOK := validScope.MatchString(scope) && !strings.Contains(scope, "..")
		policyOK := validPolicy.MatchString(policy)

		if scopeOK {
			// A scope that passes validation must not contain any of these
			// characters. If it does, our validators have a bypass.
			for _, bad := range []string{"/", "..", "\x00", " ", "\n", "?", "#", "%", ":", "@"} {
				if strings.Contains(scope, bad) {
					// "/" is allowed exactly once in owner/repo form, so only
					// flag it if more than one slash is present.
					if bad == "/" && strings.Count(scope, "/") <= 1 {
						continue
					}
					t.Fatalf("scope %q passed validation but contains %q", scope, bad)
				}
			}
		}
		if policyOK {
			for _, bad := range []string{"/", "..", "\x00", " ", "\n", "?", "#", "%", ":", "@", "."} {
				if strings.Contains(policy, bad) {
					t.Fatalf("policy %q passed validation but contains %q", policy, bad)
				}
			}
		}
	})
}
