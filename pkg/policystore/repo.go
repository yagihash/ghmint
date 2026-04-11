package policystore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var validPolicy = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type tokenIssuer interface {
	Issue(ctx context.Context, owner string) (string, error)
}

// RepoPolicyStore fetches Rego policy files from GitHub repositories via the Contents API.
//
// The policy file path is always .github/mini-gh-sts/<policy>.rego within the repository
// determined by scope:
//
//	scope="owner/repo" → owner/repo repository
//	scope="owner"      → owner/.github repository
type RepoPolicyStore struct {
	issuer tokenIssuer
}

func NewRepoPolicyStore(issuer tokenIssuer) *RepoPolicyStore {
	return &RepoPolicyStore{issuer: issuer}
}

func (r *RepoPolicyStore) Fetch(ctx context.Context, scope, policy string) ([]byte, error) {
	if !validPolicy.MatchString(policy) {
		return nil, fmt.Errorf("invalid policy name %q: must match [a-zA-Z0-9_-]+", policy)
	}

	owner, _, hasRepo := strings.Cut(scope, "/")
	var repo string
	if hasRepo {
		repo = scope
	} else {
		repo = scope + "/.github"
	}

	token, err := r.issuer.Issue(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/contents/.github/mini-gh-sts/%s.rego", repo, policy)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if result.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q", result.Encoding)
	}

	// GitHub API wraps base64 content with newlines.
	cleaned := strings.ReplaceAll(result.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64 content: %w", err)
	}

	return content, nil
}
