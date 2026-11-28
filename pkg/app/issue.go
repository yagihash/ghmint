package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/verifier"
)

type issueFailureKind int

const (
	issueInvalidAssertion issueFailureKind = iota + 1 // OIDC token verification failed
	issueDenied                                       // policy denied (fail-closed)
	issuePolicyFailed                                 // policy evaluation internal error
	issueFailed                                       // GitHub token issuance failed
)

type issueError struct{ kind issueFailureKind }

func (e *issueError) Error() string { return "token issuance failed" }

// issue is the protocol-independent core shared by the legacy JSON API and the
// RFC 7523 endpoint. Details are logged here; callers only map the kind.
func (s *server) issue(ctx context.Context, rawToken, org, scope, policy string) (installation.IssueResult, *issueError) {
	claims, err := s.oidcVerifier.Verify(ctx, rawToken)
	if err != nil {
		s.logger.WarnContext(ctx, "oidc verification failed", "error", err)
		return installation.IssueResult{}, &issueError{issueInvalidAssertion}
	}

	res, err := s.policyVerifier.Verify(ctx, claims.Raw, scope, policy)
	if err != nil {
		if policyErr, ok := errors.AsType[*verifier.DenialError](err); ok {
			if policyErr.Upstream {
				// Still fail-closed per CLAUDE.md, but logged at error level
				// and tagged so infra outages don't blend in with real denials.
				s.logger.ErrorContext(ctx, "policy denied token issuance due to upstream failure", "scope", scope, "policy", policy, "reason", policyErr.Reason)
			} else {
				s.logger.WarnContext(ctx, "policy denied token issuance", "scope", scope, "policy", policy, "reason", policyErr.Reason)
			}
			return installation.IssueResult{}, &issueError{issueDenied}
		}
		s.logger.ErrorContext(ctx, "policy evaluation failed", "error", err)
		return installation.IssueResult{}, &issueError{issuePolicyFailed}
	}

	// An unregistered App is a policy-side failure, so it is reported like any
	// other denial (fail-closed) and the name is only disclosed in the log.
	// A custom Verifier may leave App empty, which means "default".
	if res.App == "" {
		res.App = verifier.DefaultApp
	}
	issuer, ok := s.tokenIssuers[res.App]
	if !ok {
		s.logger.WarnContext(ctx, "policy denied token issuance", "scope", scope, "policy", policy, "reason", fmt.Sprintf("policy: app %q is not registered", res.App))
		return installation.IssueResult{}, &issueError{issueDenied}
	}

	result, err := issuer.IssueToken(ctx, org, res.Permissions, res.Repositories)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to issue github app token", "app", res.App, "error", err)
		return installation.IssueResult{}, &issueError{issueFailed}
	}

	h := sha256.Sum256([]byte(result.Token))
	s.logger.InfoContext(
		ctx,
		"successfully issued token",
		"subject", claims.Raw["sub"],
		"issuer", claims.Raw["iss"],
		"app", res.App,
		"hashed_token", base64.StdEncoding.EncodeToString(h[:]),
		"permissions", result.Permissions,
		"repositories", result.Repositories,
	)
	return result, nil
}
