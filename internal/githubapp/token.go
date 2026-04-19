package githubapp

import (
	"bytes"
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
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}

const (
	maxErrorBodyBytes    = 512 * 1024
	maxResponseBodyBytes = 1 * 1024 * 1024
)

type TokenIssuer struct {
	appID      string
	signer     jwtSigner
	httpClient *http.Client
}

// IssueResult holds the GitHub App Installation Access Token and its metadata.
type IssueResult struct {
	Token        string
	ExpiresAt    time.Time
	Permissions  map[string]string
	Repositories []string
}

func New(appID string, signer jwtSigner) *TokenIssuer {
	return &TokenIssuer{
		appID:      appID,
		signer:     signer,
		httpClient: http.DefaultClient,
	}
}

func (t *TokenIssuer) Issue(ctx context.Context, owner string, permissions map[string]string, repositories []string) (IssueResult, error) {
	jwt, err := t.signJWT(ctx)
	if err != nil {
		return IssueResult{}, fmt.Errorf("sign jwt: %w", err)
	}

	installationID, err := t.getInstallationID(ctx, jwt, owner)
	if err != nil {
		return IssueResult{}, fmt.Errorf("get installation id: %w", err)
	}

	return t.requestInstallationToken(ctx, jwt, installationID, permissions, repositories)
}

func (t *TokenIssuer) signJWT(ctx context.Context) (string, error) {
	now := time.Now()

	headerJSON, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256"})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss": t.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(600 * time.Second).Unix(),
	})

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload

	sig, err := t.signer.SignRS256(ctx, []byte(signingInput))
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (t *TokenIssuer) getInstallationID(ctx context.Context, jwt, owner string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/users/%s/installation", owner)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := t.httpClient.Do(req)
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

func (t *TokenIssuer) requestInstallationToken(ctx context.Context, jwt string, installationID int64, permissions map[string]string, repositories []string) (IssueResult, error) {
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

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return IssueResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
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
