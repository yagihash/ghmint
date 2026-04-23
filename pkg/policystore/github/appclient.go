package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxErrorBodyBytes    = 512 * 1024
	maxResponseBodyBytes = 1 * 1024 * 1024
	defaultHTTPTimeout   = 10 * time.Second
)

type jwtSigner interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}

type appClient struct {
	appID      string
	signer     jwtSigner
	httpClient *http.Client
	cache      *cache
}

func (c *appClient) signJWT(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *appClient) installationID(ctx context.Context, jwt, owner string) (int64, error) {
	reqURL := fmt.Sprintf("https://api.github.com/users/%s/installation", url.PathEscape(owner))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

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

func (c *appClient) installationToken(ctx context.Context, jwt string, installationID int64) (string, time.Time, error) {
	reqURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader("{}"))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
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

	// expires_at is optional in tests; fall back to 60 minutes (GitHub's default)
	// so callers always receive a meaningful expiry for cache bookkeeping.
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

// installationTokenForOwner returns a cached installation token for owner,
// refetching the installation id and/or access token as needed.
func (c *appClient) installationTokenForOwner(ctx context.Context, owner string) (string, error) {
	if tok, ok := c.cache.getInstallToken(owner); ok {
		return tok, nil
	}

	id, ok := c.cache.getInstallID(owner)
	if !ok {
		jwt, err := c.signJWT(ctx)
		if err != nil {
			return "", fmt.Errorf("create jwt: %w", err)
		}
		id, err = c.installationID(ctx, jwt, owner)
		if err != nil {
			return "", fmt.Errorf("get installation id: %w", err)
		}
		c.cache.setInstallID(owner, id)
	}

	jwt, err := c.signJWT(ctx)
	if err != nil {
		return "", fmt.Errorf("create jwt: %w", err)
	}
	token, expiresAt, err := c.installationToken(ctx, jwt, id)
	if err != nil {
		return "", fmt.Errorf("get installation token: %w", err)
	}
	c.cache.setInstallToken(owner, token, expiresAt)
	return token, nil
}

// GetFileContent fetches the content of a file in a GitHub repository.
// repo must be in "owner/repo" format.
func (c *appClient) GetFileContent(ctx context.Context, repo, path string) ([]byte, error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("repo must be in owner/repo format: %q", repo)
	}

	policyKey := repo + ":" + path
	if cached, ok := c.cache.getPolicy(policyKey); ok {
		return cached, nil
	}

	token, err := c.installationTokenForOwner(ctx, owner)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/%s",
		url.PathEscape(owner), url.PathEscape(name), path,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := c.httpClient.Do(req)
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

	c.cache.setPolicy(policyKey, content)
	return content, nil
}
