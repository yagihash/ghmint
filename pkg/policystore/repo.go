package policystore

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var validPolicy = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type githubClient interface {
	GetFileContent(ctx context.Context, repo, path string) ([]byte, error)
}

// RepoPolicyStore fetches Rego policy files from GitHub repositories via the Contents API,
// authenticating as a GitHub App using a JWT.
//
// The policy file path is always .github/mini-gh-sts/<policy>.rego within the repository
// determined by scope:
//
//	scope="owner/repo" → owner/repo repository
//	scope="owner"      → owner/.github repository
type RepoPolicyStore struct {
	client githubClient
}

func NewRepoPolicyStore(client githubClient) *RepoPolicyStore {
	return &RepoPolicyStore{client: client}
}

func (r *RepoPolicyStore) Fetch(ctx context.Context, scope, policy string) ([]byte, error) {
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

	path := fmt.Sprintf(".github/mini-gh-sts/%s.rego", policy)
	return r.client.GetFileContent(ctx, repo, path)
}
