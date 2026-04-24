package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/signer"
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

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newMockGitHub returns a test server that handles the full GitHub App auth flow
// (installationID → installationToken → contents) and captures the contents request path.
func newMockGitHub(t *testing.T, content []byte, capturedPath *string) *httptest.Server {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token": "test-installation-token",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			if capturedPath != nil {
				*capturedPath = r.URL.Path
			}
			json.NewEncoder(w).Encode(map[string]any{
				"content":  encoded,
				"encoding": "base64",
			})
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestStore(t *testing.T, srv *httptest.Server) *RepoPolicyStore {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	httpClient := &http.Client{Transport: &redirectTransport{target: u}}
	installClient := installation.New("test-app", &testSigner{key: mustKey(t)},
		installation.WithHTTPClient(httpClient))
	return NewRepoPolicyStore(installClient, WithHTTPClient(httpClient))
}

func newNoNetworkStore(t *testing.T) *RepoPolicyStore {
	t.Helper()
	return NewRepoPolicyStore(installation.New("app", &testSigner{key: mustKey(t)}))
}

// --- Fetch: policy name validation ---

func TestFetch_InvalidPolicyName(t *testing.T) {
	cases := []string{"../../etc/passwd", "policy name", "policy/name", ""}
	store := newNoNetworkStore(t)
	for _, name := range cases {
		if _, err := store.Fetch(context.Background(), "org/repo", name); err == nil {
			t.Errorf("expected error for policy name %q", name)
		}
	}
}

// --- Fetch: scope validation ---

func TestFetch_InvalidScope(t *testing.T) {
	cases := []string{"org/repo/../evil", "org/repo/extra", "org?q=1", "org/repo#frag", "org/../evil", "/repo", "", "org/..", "org/."}
	store := newNoNetworkStore(t)
	for _, scope := range cases {
		if _, err := store.Fetch(context.Background(), scope, "policy"); err == nil {
			t.Errorf("expected error for scope %q, got nil", scope)
		}
	}
}

// --- Fetch: scope → repo resolution ---

func TestFetch_OrgScope_UsesGithubRepo(t *testing.T) {
	var capturedPath string
	srv := newMockGitHub(t, []byte("package ghmint"), &capturedPath)
	store := newTestStore(t, srv)

	store.Fetch(context.Background(), "myorg", "policy")

	if !strings.Contains(capturedPath, "myorg/.github") {
		t.Errorf("expected path to contain myorg/.github, got %q", capturedPath)
	}
	if !strings.Contains(capturedPath, "policy.rego") {
		t.Errorf("expected path to contain policy.rego, got %q", capturedPath)
	}
}

func TestFetch_OrgRepoScope_UsesScopeRepo(t *testing.T) {
	var capturedPath string
	srv := newMockGitHub(t, []byte("package ghmint"), &capturedPath)
	store := newTestStore(t, srv)

	store.Fetch(context.Background(), "myorg/myrepo", "policy")

	if !strings.Contains(capturedPath, "myorg/myrepo") {
		t.Errorf("expected path to contain myorg/myrepo, got %q", capturedPath)
	}
	if strings.Contains(capturedPath, ".github/myorg") {
		t.Errorf("unexpected .github repo for org/repo scope, got %q", capturedPath)
	}
}

func TestFetch_Success_ReturnsDecodedContent(t *testing.T) {
	expected := []byte("package ghmint\n\nallow := true")
	srv := newMockGitHub(t, expected, nil)
	store := newTestStore(t, srv)

	got, err := store.Fetch(context.Background(), "org/repo", "policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(expected) {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

// --- getFileContent error cases ---

func TestFetch_Non200Contents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"token": "tok"})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"message": "Not Found"})
		}
	}))
	defer srv.Close()

	store := newTestStore(t, srv)
	if _, err := store.Fetch(context.Background(), "org/repo", "policy"); err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestFetch_UnexpectedEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"token": "tok"})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"content":  "aGVsbG8=",
				"encoding": "utf-8",
			})
		}
	}))
	defer srv.Close()

	store := newTestStore(t, srv)
	if _, err := store.Fetch(context.Background(), "org/repo", "policy"); err == nil {
		t.Fatal("expected error for unexpected encoding")
	}
}

func TestFetch_InstallationTokenFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/installation") {
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	store := newTestStore(t, srv)
	if _, err := store.Fetch(context.Background(), "org/repo", "policy"); err == nil {
		t.Fatal("expected error for failed installation token")
	}
}

func TestFetch_LimitReader(t *testing.T) {
	oversized := strings.Repeat("x", maxResponseBodyBytes+1)
	encoded := base64.StdEncoding.EncodeToString([]byte(oversized))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/installation"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case strings.Contains(r.URL.Path, "/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"token": "tok"})
		default:
			fmt.Fprintf(w, `{"content":%q,"encoding":"base64"}`, encoded)
		}
	}))
	defer srv.Close()

	store := newTestStore(t, srv)
	// Should not panic or OOM; error or truncated result are both acceptable.
	store.Fetch(context.Background(), "org/repo", "policy")
}

// --- Cache behavior ---

// countingSigner wraps a signer.Signer and records how many times SignRS256 is
// invoked, letting tests assert KMS round-trip counts.
type countingSigner struct {
	inner signer.Signer
	mu    sync.Mutex
	count int
}

func (s *countingSigner) SignRS256(ctx context.Context, data []byte) ([]byte, error) {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	return s.inner.SignRS256(ctx, data)
}

func (s *countingSigner) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// TestFetch_Caches ensures that repeated Fetch calls hit the GitHub contents
// API (and the signer) at most once per policy per TTL window.
func TestFetch_Caches(t *testing.T) {
	var (
		mu           sync.Mutex
		installHits  int
		tokenHits    int
		contentsHits int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/installation"):
			mu.Lock()
			installHits++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			mu.Lock()
			tokenHits++
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "test-installation-token",
				"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			mu.Lock()
			contentsHits++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{
				"content":  base64.StdEncoding.EncodeToString([]byte("package ghmint")),
				"encoding": "base64",
			})
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	httpClient := &http.Client{Transport: &redirectTransport{target: u}}
	cs := &countingSigner{inner: &testSigner{key: mustKey(t)}}
	installClient := installation.New("test-app", cs, installation.WithHTTPClient(httpClient))
	store := NewRepoPolicyStore(installClient, WithHTTPClient(httpClient))

	for range 3 {
		if _, err := store.Fetch(context.Background(), "org/repo", "policy"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if installHits != 1 {
		t.Errorf("expected 1 installation-id request, got %d", installHits)
	}
	if tokenHits != 1 {
		t.Errorf("expected 1 installation-token request, got %d", tokenHits)
	}
	if contentsHits != 1 {
		t.Errorf("expected 1 contents request (rest served from cache), got %d", contentsHits)
	}
	// Cold cache requires one JWT (shared across installation-id +
	// installation-token); subsequent Fetches serve from the cached access
	// token and must not re-sign.
	if n := cs.Count(); n != 1 {
		t.Errorf("expected 1 JWT signing across all Fetches, got %d", n)
	}
}

// suppress unused import warning
var _ = time.Second
