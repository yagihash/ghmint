package installation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yagihash/ghmint/pkg/signer"
)

const (
	maxErrorBodyBytes    = 512 * 1024
	maxResponseBodyBytes = 1 * 1024 * 1024
	defaultHTTPTimeout   = 10 * time.Second
	apiVersion           = "2026-03-10"
)

// IssueResult holds the GitHub App Installation Access Token and its metadata.
type IssueResult struct {
	Token        string
	ExpiresAt    time.Time
	Permissions  map[string]string
	Repositories []string
}

// Client authenticates as a GitHub App and provides installation access tokens.
// It caches installation IDs (60 min) and plain tokens (expires_at - 5 min).
// A single Client should be shared across all components to maximize cache reuse.
type Client struct {
	appID      string
	signer     signer.Signer
	httpClient *http.Client
	cache      *cache
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient injects a custom HTTP client (useful in tests).
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

// New creates a Client using the given GitHub App ID and RS256 signer.
func New(appID string, s signer.Signer, opts ...Option) *Client {
	c := &Client{
		appID:      appID,
		signer:     s,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
		cache:      newCache(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// TokenForOwner returns a cached installation access token for the given owner.
// Suitable for general GitHub API calls (policystore, webhook).
func (c *Client) TokenForOwner(ctx context.Context, owner string) (string, error) {
	if tok, ok := c.cache.getToken(owner); ok {
		return tok, nil
	}

	jwt, err := c.signJWT(ctx)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	id, ok := c.cache.getInstallID(owner)
	if !ok {
		id, err = c.installationID(ctx, jwt, owner)
		if err != nil {
			return "", fmt.Errorf("get installation id: %w", err)
		}
		c.cache.setInstallID(owner, id)
	}

	token, expiresAt, err := c.installationToken(ctx, jwt, id)
	if err != nil {
		return "", fmt.Errorf("get installation token: %w", err)
	}
	c.cache.setToken(owner, token, expiresAt)
	return token, nil
}

// IssueToken issues a GitHub App Installation Access Token scoped to the given
// permissions and repositories. Unlike TokenForOwner, results are not cached
// because the token is specific to the requested permissions.
func (c *Client) IssueToken(ctx context.Context, owner string, permissions map[string]string, repositories []string) (IssueResult, error) {
	jwt, err := c.signJWT(ctx)
	if err != nil {
		return IssueResult{}, fmt.Errorf("sign jwt: %w", err)
	}

	id, ok := c.cache.getInstallID(owner)
	if !ok {
		id, err = c.installationID(ctx, jwt, owner)
		if err != nil {
			return IssueResult{}, fmt.Errorf("get installation id: %w", err)
		}
		c.cache.setInstallID(owner, id)
	}

	return c.issueToken(ctx, jwt, id, permissions, repositories)
}

func (c *Client) signJWT(ctx context.Context) (string, error) {
	now := time.Now()
	headerJSON, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256"})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss": c.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(600 * time.Second).Unix(),
	})
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	sig, err := c.signer.SignRS256(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) installationID(ctx context.Context, jwt, owner string) (int64, error) {
	reqURL := fmt.Sprintf("https://api.github.com/users/%s/installation", url.PathEscape(owner))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, jwt)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return 0, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return result.ID, nil
}

func (c *Client) installationToken(ctx context.Context, jwt string, installID int64) (string, time.Time, error) {
	reqURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader("{}"))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, jwt)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return "", time.Time{}, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode response: %w", err)
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("empty token in response")
	}
	expiresAt := time.Now().Add(60 * time.Minute)
	if result.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, result.ExpiresAt)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("parse expires_at: %w", err)
		}
		expiresAt = t
	}
	return result.Token, expiresAt, nil
}

func (c *Client) issueToken(ctx context.Context, jwt string, installID int64, permissions map[string]string, repositories []string) (IssueResult, error) {
	repoNames := make([]string, 0, len(repositories))
	for _, r := range repositories {
		_, name, found := strings.Cut(r, "/")
		if found {
			repoNames = append(repoNames, name)
		}
	}

	reqBody := struct {
		Permissions  map[string]string `json:"permissions,omitempty"`
		Repositories []string          `json:"repositories,omitempty"`
	}{
		Permissions:  permissions,
		Repositories: repoNames,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return IssueResult{}, fmt.Errorf("marshal request body: %w", err)
	}

	reqURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return IssueResult{}, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, jwt)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return IssueResult{}, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errBody struct {
			Message string `json:"message"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodyBytes)).Decode(&errBody)
		return IssueResult{}, fmt.Errorf("github api returned %d: %s", resp.StatusCode, errBody.Message)
	}

	var result struct {
		Token       string            `json:"token"`
		ExpiresAt   string            `json:"expires_at"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&result); err != nil {
		return IssueResult{}, fmt.Errorf("decode response: %w", err)
	}
	if result.Token == "" {
		return IssueResult{}, fmt.Errorf("empty token in response")
	}
	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return IssueResult{}, fmt.Errorf("parse expires_at: %w", err)
	}
	return IssueResult{
		Token:        result.Token,
		ExpiresAt:    expiresAt,
		Permissions:  result.Permissions,
		Repositories: repositories,
	}, nil
}

func (c *Client) setHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
}
