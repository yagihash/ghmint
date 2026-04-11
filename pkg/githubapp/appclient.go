package githubapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type jwtSigner interface {
	SignRS256([]byte) ([]byte, error)
}

// AppClient is a GitHub API client that authenticates as a GitHub App using a JWT.
// A fresh JWT is generated per API call since JWTs are short-lived (up to 10 minutes).
type AppClient struct {
	appID  string
	signer jwtSigner
}

func NewAppClient(appID string, signer jwtSigner) *AppClient {
	return &AppClient{appID: appID, signer: signer}
}

func (c *AppClient) jwt() (string, error) {
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

	sig, err := c.signer.SignRS256([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *AppClient) installationID(ctx context.Context, jwt, owner string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/installation", owner)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	return result.ID, nil
}

func (c *AppClient) installationToken(ctx context.Context, jwt string, installationID int64) (string, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(`{"permissions":{"contents":"read"}}`))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github api returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}
	return result.Token, nil
}

// GetFileContent fetches the content of a file in a GitHub repository.
// repo is in "owner/repo" format, path is the file path within the repository.
// It authenticates as a GitHub App installation to access the repository contents.
func (c *AppClient) GetFileContent(ctx context.Context, repo, path string) ([]byte, error) {
	owner, _, _ := strings.Cut(repo, "/")

	jwt, err := c.jwt()
	if err != nil {
		return nil, fmt.Errorf("create jwt: %w", err)
	}

	id, err := c.installationID(ctx, jwt, owner)
	if err != nil {
		return nil, fmt.Errorf("get installation id: %w", err)
	}

	token, err := c.installationToken(ctx, jwt, id)
	if err != nil {
		return nil, fmt.Errorf("get installation token: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repo, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

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
