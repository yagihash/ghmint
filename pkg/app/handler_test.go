package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yagihash/mini-gh-sts/pkg/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/policyerrors"
)

// --- mocks ---

type mockOIDCVerifier struct {
	claims minioidc.Claims
	err    error
}

func (m *mockOIDCVerifier) Verify(_ context.Context, _ string) (minioidc.Claims, error) {
	return m.claims, m.err
}

type mockTokenIssuer struct {
	result githubapp.IssueResult
	err    error
}

func (m *mockTokenIssuer) Issue(_ context.Context, _ string, _ map[string]string, _ []string) (githubapp.IssueResult, error) {
	return m.result, m.err
}

type mockPolicyVerifier struct {
	permissions map[string]string
	repos       []string
	err         error
}

func (m *mockPolicyVerifier) Verify(_ context.Context, _ map[string]interface{}, _, _ string) (map[string]string, []string, error) {
	return m.permissions, m.repos, m.err
}

type testLog struct{}

func (testLog) DebugContext(_ context.Context, _ string, _ ...any) {}
func (testLog) InfoContext(_ context.Context, _ string, _ ...any)  {}
func (testLog) WarnContext(_ context.Context, _ string, _ ...any)  {}
func (testLog) ErrorContext(_ context.Context, _ string, _ ...any) {}
func (l testLog) With(_ ...any) logger.Logger                      { return l }

// --- helper ---

func newTestServer(ov oidcVerifier, ti tokenIssuer, pv policyVerifier) *server {
	return newServer(testLog{}, ov, ti, pv, Config{})
}

// --- tests ---

func TestHandleHealthz(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.handleHealthz(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "{}" {
		t.Errorf("expected body={}, got %q", body)
	}
}

func tokenRequestBody(scope, policy string) *strings.Reader {
	return strings.NewReader(`{"scope":"` + scope + `","policy":"` + policy + `"}`)
}

func TestHandleToken_MissingContentType(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", rr.Code)
	}
	assertCode(t, rr, "UNSUPPORTED_MEDIA_TYPE")
}

func TestHandleToken_MissingAuthorization(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	assertCode(t, rr, "BAD_REQUEST")
}

func TestHandleToken_MissingScope(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"scope":"","policy":"pol"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	assertCode(t, rr, "MISSING_SCOPE")
}

func TestHandleToken_MissingPolicy(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"scope":"org/repo","policy":""}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	assertCode(t, rr, "MISSING_POLICY")
}

func TestHandleToken_InvalidOIDCToken(t *testing.T) {
	ov := &mockOIDCVerifier{err: errors.New("invalid token")}
	srv := newTestServer(ov, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	assertCode(t, rr, "INVALID_TOKEN")
}

func TestHandleToken_PolicyDenialError(t *testing.T) {
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]interface{}{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{err: &policyerrors.DenialError{Reason: "denied"}}
	srv := newTestServer(ov, nil, pv)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	assertCode(t, rr, "FORBIDDEN")
}

func TestHandleToken_PolicyInternalError(t *testing.T) {
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]interface{}{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{err: errors.New("internal policy error")}
	srv := newTestServer(ov, nil, pv)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	assertCode(t, rr, "INTERNAL_ERROR")
}

func TestHandleToken_TokenIssueError(t *testing.T) {
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]interface{}{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{permissions: map[string]string{"contents": "read"}, repos: []string{"org/repo"}}
	ti := &mockTokenIssuer{err: errors.New("github api error")}
	srv := newTestServer(ov, ti, pv)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	assertCode(t, rr, "INTERNAL_ERROR")
}

func TestHandleToken_Success(t *testing.T) {
	expiresAt := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]interface{}{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{
		permissions: map[string]string{"contents": "read"},
		repos:       []string{"org/repo"},
	}
	ti := &mockTokenIssuer{result: githubapp.IssueResult{
		Token:        "ghs_test",
		ExpiresAt:    expiresAt,
		Permissions:  map[string]string{"contents": "read"},
		Repositories: []string{"org/repo"},
	}}
	srv := newTestServer(ov, ti, pv)
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Token        string            `json:"token"`
		ExpiresAt    string            `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token != "ghs_test" {
		t.Errorf("expected token=ghs_test, got %q", resp.Token)
	}
	if resp.ExpiresAt != "2026-04-13T12:00:00Z" {
		t.Errorf("expected expires_at=2026-04-13T12:00:00Z, got %q", resp.ExpiresAt)
	}
	if resp.Permissions["contents"] != "read" {
		t.Errorf("expected permissions[contents]=read, got %v", resp.Permissions)
	}
	if len(resp.Repositories) != 1 || resp.Repositories[0] != "org/repo" {
		t.Errorf("expected repositories=[org/repo], got %v", resp.Repositories)
	}
}

// assertCode は JSON レスポンスボディの "code" フィールドを検証する。
func assertCode(t *testing.T, rr *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != want {
		t.Errorf("expected code=%q, got %q", want, body.Code)
	}
}
