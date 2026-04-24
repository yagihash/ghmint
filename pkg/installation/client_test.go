package installation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type redirectTransport struct {
	target *url.URL
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = t.target.Host
	req.URL.Scheme = t.target.Scheme
	return http.DefaultTransport.RoundTrip(req)
}

type testSigner struct {
	key *rsa.PrivateKey
}

func (s *testSigner) SignRS256(_ context.Context, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, h[:])
}

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return New("app-123", &testSigner{key: key}, WithHTTPClient(&http.Client{
		Transport: &redirectTransport{target: u},
	}))
}

func installationHandler(installID int, tokenBody map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": installID})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(tokenBody)
		}
	}
}

func TestIssueToken_Success(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	srv := httptest.NewServer(installationHandler(42, map[string]any{
		"token":       "ghs_test_token",
		"expires_at":  expiresAt.Format(time.RFC3339),
		"permissions": map[string]string{"contents": "read"},
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	result, err := c.IssueToken(context.Background(), "myorg", map[string]string{"contents": "read"}, []string{"myorg/repo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Token != "ghs_test_token" {
		t.Errorf("expected token=ghs_test_token, got %q", result.Token)
	}
	if !result.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expected expires_at=%v, got %v", expiresAt, result.ExpiresAt)
	}
}

func TestIssueToken_InstallationNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	if _, err := c.IssueToken(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for 404 installation")
	}
}

func TestIssueToken_TokenCreationFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"message": "Forbidden"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	if _, err := c.IssueToken(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for 403 token creation")
	}
}

func TestIssueToken_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	if _, err := c.IssueToken(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for empty token in response")
	}
}

func TestIssueToken_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.IssueToken(ctx, "myorg", nil, nil); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestIssueToken_RepoNamesStripped(t *testing.T) {
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
			return
		}
		json.NewDecoder(r.Body).Decode(&capturedBody)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_x",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.IssueToken(context.Background(), "myorg", nil, []string{"myorg/repo-a", "myorg/repo-b"})

	repos, _ := capturedBody["repositories"].([]any)
	if len(repos) != 2 || repos[0] != "repo-a" || repos[1] != "repo-b" {
		t.Errorf("expected repositories=[repo-a repo-b] in request body, got %v", repos)
	}
}

func TestTokenForOwner_Cached(t *testing.T) {
	calls := 0
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "ghs_cached",
				"expires_at": expiresAt.Format(time.RFC3339),
			})
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	for range 3 {
		tok, err := c.TokenForOwner(context.Background(), "myorg")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok != "ghs_cached" {
			t.Errorf("expected ghs_cached, got %q", tok)
		}
	}
	if calls > 2 {
		// First call: GET installation + POST access_tokens. Subsequent calls: cached.
		t.Errorf("expected at most 2 API calls, got %d", calls)
	}
}
