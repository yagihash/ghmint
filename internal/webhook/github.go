package webhook

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
	"sync"
	"time"
)

const (
	maxWebhookErrorBody    = 512 * 1024
	maxWebhookResponseBody = 1 * 1024 * 1024
	webhookHTTPTimeout     = 30 * time.Second
	annotationsPerRequest  = 50
	checkRunName           = "ghmint / policy validation"
	githubAPIVersion       = "2026-03-10"
)

type jwtSigner interface {
	SignRS256(ctx context.Context, data []byte) ([]byte, error)
}

type tokenEntry struct {
	token     string
	expiresAt time.Time
}

type githubClient struct {
	appID      string
	signer     jwtSigner
	httpClient *http.Client
	mu         sync.Mutex
	tokens     map[string]tokenEntry
}

func newGithubClient(appID string, s jwtSigner) *githubClient {
	return &githubClient{
		appID:      appID,
		signer:     s,
		httpClient: &http.Client{Timeout: webhookHTTPTimeout},
		tokens:     make(map[string]tokenEntry),
	}
}

func (c *githubClient) signJWT(ctx context.Context) (string, error) {
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

func (c *githubClient) tokenForOwner(ctx context.Context, owner string) (string, error) {
	c.mu.Lock()
	if e, ok := c.tokens[owner]; ok && time.Now().Before(e.expiresAt) {
		tok := e.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	jwt, err := c.signJWT(ctx)
	if err != nil {
		return "", err
	}

	installID, err := c.installationID(ctx, jwt, owner)
	if err != nil {
		return "", err
	}

	token, expiresAt, err := c.installationToken(ctx, jwt, installID)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.tokens[owner] = tokenEntry{token: token, expiresAt: expiresAt.Add(-5 * time.Minute)}
	c.mu.Unlock()

	return token, nil
}

func (c *githubClient) installationID(ctx context.Context, jwt, owner string) (int64, error) {
	reqURL := fmt.Sprintf("https://api.github.com/users/%s/installation", url.PathEscape(owner))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, jwt)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		return 0, fmt.Errorf("github api returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebhookResponseBody)).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	return result.ID, nil
}

func (c *githubClient) installationToken(ctx context.Context, jwt string, installID int64) (string, time.Time, error) {
	reqURL := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader("{}"))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, jwt)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		return "", time.Time{}, fmt.Errorf("github api returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebhookResponseBody)).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode: %w", err)
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

// listPRFiles returns paths of changed files in the PR that match .github/ghmint/*.rego.
func (c *githubClient) listPRFiles(ctx context.Context, token, owner, repo string, pr int) ([]string, error) {
	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/files",
		url.PathEscape(owner), url.PathEscape(repo), pr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		return nil, fmt.Errorf("github api returned %d: %s", resp.StatusCode, body)
	}

	var files []struct {
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebhookResponseBody)).Decode(&files); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	var result []string
	for _, f := range files {
		if strings.HasPrefix(f.Filename, ".github/ghmint/") && strings.HasSuffix(f.Filename, ".rego") {
			result = append(result, f.Filename)
		}
	}
	return result, nil
}

// getFileContent fetches the content of a file at a specific ref (commit SHA or branch).
func (c *githubClient) getFileContent(ctx context.Context, token, owner, repo, path, ref string) ([]byte, error) {
	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		url.PathEscape(owner), url.PathEscape(repo),
		escapePathSegments(path), url.QueryEscape(ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		return nil, fmt.Errorf("github api returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebhookResponseBody)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if result.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding %q", result.Encoding)
	}
	cleaned := strings.ReplaceAll(result.Content, "\n", "")
	content, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return content, nil
}

// createCheckRun creates an in-progress check run and returns its ID.
func (c *githubClient) createCheckRun(ctx context.Context, token, owner, repo, headSHA string) (int64, error) {
	body, _ := json.Marshal(map[string]any{
		"name":     checkRunName,
		"head_sha": headSHA,
		"status":   "in_progress",
	})
	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/check-runs",
		url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		return 0, fmt.Errorf("github api returned %d: %s", resp.StatusCode, b)
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebhookResponseBody)).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	return result.ID, nil
}

type annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
}

// updateCheckRun marks the check run as completed and sends annotations in batches of 50.
func (c *githubClient) updateCheckRun(ctx context.Context, token, owner, repo string, id int64, conclusion string, annotations []annotation, summary string) error {
	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/check-runs/%d",
		url.PathEscape(owner), url.PathEscape(repo), id)

	patch := func(batch []annotation, final bool) error {
		output := map[string]any{
			"title":       "Rego Policy Validation",
			"summary":     summary,
			"annotations": batch,
		}
		payload := map[string]any{"output": output}
		if final {
			payload["status"] = "completed"
			payload["conclusion"] = conclusion
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		c.setHeaders(req, token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("github api: %w", err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrorBody))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("github api returned %d: %s", resp.StatusCode, b)
		}
		return nil
	}

	if len(annotations) == 0 {
		return patch([]annotation{}, true)
	}

	for i := 0; i < len(annotations); i += annotationsPerRequest {
		end := i + annotationsPerRequest
		if end > len(annotations) {
			end = len(annotations)
		}
		if err := patch(annotations[i:end], end >= len(annotations)); err != nil {
			return err
		}
	}
	return nil
}

func (c *githubClient) setHeaders(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
}

func escapePathSegments(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
