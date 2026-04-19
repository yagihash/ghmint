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
	client := &http.Client{Transport: &redirectTransport{target: u}}
	return NewRepoPolicyStore("test-app", &testSigner{key: mustKey(t)}, WithHTTPClient(client))
}

// --- Fetch: policy name validation ---

func TestFetch_InvalidPolicyName(t *testing.T) {
	cases := []string{"../../etc/passwd", "policy name", "policy/name", ""}
	store := NewRepoPolicyStore("app", &testSigner{key: mustKey(t)})
	for _, name := range cases {
		if _, err := store.Fetch(context.Background(), "org/repo", name); err == nil {
			t.Errorf("expected error for policy name %q", name)
		}
	}
}

// --- Fetch: scope → repo resolution ---

func TestFetch_OrgScope_UsesGithubRepo(t *testing.T) {
	var capturedPath string
	srv := newMockGitHub(t, []byte("package mini_gh_sts"), &capturedPath)
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
	srv := newMockGitHub(t, []byte("package mini_gh_sts"), &capturedPath)
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
	expected := []byte("package mini_gh_sts\n\nallow := true")
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

// --- GetFileContent ---

func TestGetFileContent_Non200(t *testing.T) {
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

	u, _ := url.Parse(srv.URL)
	c := &appClient{
		appID:      "app",
		signer:     &testSigner{key: mustKey(t)},
		httpClient: &http.Client{Transport: &redirectTransport{target: u}},
	}
	if _, err := c.GetFileContent(context.Background(), "org/repo", "path/to/file.rego"); err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestGetFileContent_UnexpectedEncoding(t *testing.T) {
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
				"encoding": "utf-8", // unexpected
			})
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	c := &appClient{
		appID:      "app",
		signer:     &testSigner{key: mustKey(t)},
		httpClient: &http.Client{Transport: &redirectTransport{target: u}},
	}
	if _, err := c.GetFileContent(context.Background(), "org/repo", "file.rego"); err == nil {
		t.Fatal("expected error for unexpected encoding")
	}
}

func TestGetFileContent_InstallationTokenFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/installation") {
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
			return
		}
		// access_tokens endpoint returns error
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	c := &appClient{
		appID:      "app",
		signer:     &testSigner{key: mustKey(t)},
		httpClient: &http.Client{Transport: &redirectTransport{target: u}},
	}
	if _, err := c.GetFileContent(context.Background(), "org/repo", "file.rego"); err == nil {
		t.Fatal("expected error for failed installation token")
	}
}

func TestGetFileContent_LimitReader(t *testing.T) {
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
			// Simulate a huge JSON response; encoding field comes after the large content.
			// We just return oversized base64 content so LimitReader truncates it,
			// which should cause json.Decoder to fail or return truncated data.
			fmt.Fprintf(w, `{"content":%q,"encoding":"base64"}`, encoded)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	c := &appClient{
		appID:      "app",
		signer:     &testSigner{key: mustKey(t)},
		httpClient: &http.Client{Transport: &redirectTransport{target: u}},
	}
	// Should not panic or OOM; error or truncated result are both acceptable.
	c.GetFileContent(context.Background(), "org/repo", "file.rego")
}

// suppress unused import warning — time is used in other tests added via newMockGitHub
var _ = time.Second
