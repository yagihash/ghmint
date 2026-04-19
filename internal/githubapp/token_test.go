package githubapp

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

// redirectTransport rewrites the host of every request to the target server.
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

func newTestTokenIssuer(t *testing.T, srv *httptest.Server) *TokenIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	ti := New("app-123", &testSigner{key: key})
	ti.httpClient = &http.Client{Transport: &redirectTransport{target: u}}
	return ti
}

func TestIssue_Success(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 42})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":       "ghs_test_token",
				"expires_at":  expiresAt.Format(time.RFC3339),
				"permissions": map[string]string{"contents": "read"},
			})
		}
	}))
	defer srv.Close()

	ti := newTestTokenIssuer(t, srv)
	result, err := ti.Issue(context.Background(), "myorg", map[string]string{"contents": "read"}, []string{"myorg/repo"})
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

func TestIssue_InstallationNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
	}))
	defer srv.Close()

	ti := newTestTokenIssuer(t, srv)
	if _, err := ti.Issue(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for 404 installation")
	}
}

func TestIssue_TokenCreationFailed(t *testing.T) {
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

	ti := newTestTokenIssuer(t, srv)
	if _, err := ti.Issue(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for 403 token creation")
	}
}

func TestIssue_EmptyToken(t *testing.T) {
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

	ti := newTestTokenIssuer(t, srv)
	if _, err := ti.Issue(context.Background(), "myorg", nil, nil); err == nil {
		t.Fatal("expected error for empty token in response")
	}
}

func TestIssue_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	ti := newTestTokenIssuer(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ti.Issue(ctx, "myorg", nil, nil); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestIssue_RepoNamesStripped(t *testing.T) {
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

	ti := newTestTokenIssuer(t, srv)
	ti.Issue(context.Background(), "myorg", nil, []string{"myorg/repo-a", "myorg/repo-b"})

	repos, _ := capturedBody["repositories"].([]any)
	if len(repos) != 2 || repos[0] != "repo-a" || repos[1] != "repo-b" {
		t.Errorf("expected repositories=[repo-a repo-b] in request body, got %v", repos)
	}
}
