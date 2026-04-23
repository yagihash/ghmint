package github

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var validPolicy = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var validScope = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)?$`)

// Option configures RepoPolicyStore.
type Option func(*RepoPolicyStore)

// WithHTTPClient injects a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(r *RepoPolicyStore) {
		r.client.httpClient = c
	}
}

// RepoPolicyStore fetches Rego policy files from GitHub repositories via the Contents API,
// authenticating as a GitHub App using a JWT.
//
// The policy file path is always .github/ghmint/<policy>.rego within the repository
// determined by scope:
//
//	scope="owner/repo" → owner/repo repository
//	scope="owner"      → owner/.github repository
type RepoPolicyStore struct {
	client *appClient
}

func NewRepoPolicyStore(appID string, signer jwtSigner, opts ...Option) *RepoPolicyStore {
	r := &RepoPolicyStore{
		client: &appClient{
			appID:      appID,
			signer:     signer,
			httpClient: http.DefaultClient,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *RepoPolicyStore) Fetch(ctx context.Context, scope, policy string) ([]byte, error) {
	if !validScope.MatchString(scope) || strings.Contains(scope, "..") {
		return nil, fmt.Errorf("invalid scope %q: must match [a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)?", scope)
	}
	if !validPolicy.MatchString(policy) {
		return nil, fmt.Errorf("invalid policy name %q: must match [a-zA-Z0-9_-]+", policy)
	}

	_, _, hasRepo := strings.Cut(scope, "/")
	var repo string
	if hasRepo {
		repo = scope
	} else {
		repo = scope + "/.github"
	}

	path := fmt.Sprintf(".github/ghmint/%s.rego", policy)
	return r.client.GetFileContent(ctx, repo, path)
}
