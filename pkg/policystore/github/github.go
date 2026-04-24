package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/yagihash/ghmint/pkg/installation"
)

const (
	maxErrorBodyBytes    = 512 * 1024
	maxResponseBodyBytes = 1 * 1024 * 1024
	defaultHTTPTimeout   = 10 * time.Second
)

var validPolicy = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var validScope = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)?$`)

// Option configures RepoPolicyStore.
type Option func(*RepoPolicyStore)

// WithHTTPClient injects a custom HTTP client for GitHub Contents API calls.
func WithHTTPClient(c *http.Client) Option {
	return func(r *RepoPolicyStore) { r.httpClient = c }
}

// RepoPolicyStore fetches Rego policy files from GitHub repositories via the Contents API.
//
// The policy file path is always .github/ghmint/<policy>.rego within the repository
// determined by scope:
//
//	scope="owner/repo" → owner/repo repository
//	scope="owner"      → owner/.github repository
type RepoPolicyStore struct {
	installClient *installation.Client
	httpClient    *http.Client
	cache         *policyCache
}

// NewRepoPolicyStore creates a RepoPolicyStore using the provided installation.Client for auth.
func NewRepoPolicyStore(client *installation.Client, opts ...Option) *RepoPolicyStore {
	r := &RepoPolicyStore{
		installClient: client,
		httpClient:    &http.Client{Timeout: defaultHTTPTimeout},
		cache:         newPolicyCache(),
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
	cacheKey := repo + ":" + path

	if cached, ok := r.cache.get(cacheKey); ok {
		return cached, nil
	}

	owner, _, _ := strings.Cut(repo, "/")
	token, err := r.installClient.TokenForOwner(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	content, err := r.getFileContent(ctx, token, repo, path)
	if err != nil {
		return nil, err
	}

	r.cache.set(cacheKey, content)
	return content, nil
}

func (r *RepoPolicyStore) getFileContent(ctx context.Context, token, repo, path string) ([]byte, error) {
	ownerName, repoName, ok := strings.Cut(repo, "/")
	if !ok || ownerName == "" || repoName == "" {
		return nil, fmt.Errorf("repo must be in owner/repo format: %q", repo)
	}

	reqURL := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/%s",
		url.PathEscape(ownerName), url.PathEscape(repoName), escapePathSegments(path),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if result.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q", result.Encoding)
	}

	cleaned := strings.ReplaceAll(result.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64 content: %w", err)
	}
	return content, nil
}

func escapePathSegments(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
