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
	"time"

	"github.com/yagihash/ghmint/pkg/installation"
)

const (
	maxWebhookErrorBody    = 512 * 1024
	maxWebhookResponseBody = 1 * 1024 * 1024
	webhookHTTPTimeout     = 30 * time.Second
	annotationsPerRequest  = 50
	checkRunName           = "ghmint / policy validation"
	githubAPIVersion       = "2026-03-10"
)

type githubClient struct {
	installClient *installation.Client
	httpClient    *http.Client
}

func newGithubClient(client *installation.Client) *githubClient {
	return &githubClient{
		installClient: client,
		httpClient:    &http.Client{Timeout: webhookHTTPTimeout},
	}
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
