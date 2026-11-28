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

	minioidc "github.com/yagihash/ghmint/internal/oidc"
	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/logger"
	"github.com/yagihash/ghmint/pkg/verifier"
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
	result installation.IssueResult
	err    error
	calls  int
}

func (m *mockTokenIssuer) IssueToken(_ context.Context, _ string, _ map[string]string, _ []string) (installation.IssueResult, error) {
	m.calls++
	return m.result, m.err
}

type mockPolicyVerifier struct {
	permissions map[string]string
	repos       []string
	app         string // empty means the policy omitted "app" (-> default)
	err         error
}

func (m *mockPolicyVerifier) Verify(_ context.Context, _ map[string]any, _, _ string) (verifier.Result, error) {
	if m.err != nil {
		return verifier.Result{}, m.err
	}
	app := m.app
	if app == "" {
		app = verifier.DefaultApp
	}
	return verifier.Result{Permissions: m.permissions, Repositories: m.repos, App: app}, nil
}

type testLog struct{}

func (testLog) DebugContext(_ context.Context, _ string, _ ...any) {}
func (testLog) InfoContext(_ context.Context, _ string, _ ...any)  {}
func (testLog) WarnContext(_ context.Context, _ string, _ ...any)  {}
func (testLog) ErrorContext(_ context.Context, _ string, _ ...any) {}
func (l testLog) With(_ ...any) logger.Logger                      { return l }

// --- helper ---

func newTestServer(ov oidcVerifier, ti tokenIssuer, pv policyVerifier) *server {
	return newTestServerApps(ov, map[string]tokenIssuer{verifier.DefaultApp: ti}, pv)
}

func newTestServerApps(ov oidcVerifier, issuers map[string]tokenIssuer, pv policyVerifier) *server {
	return newServer(testLog{}, ov, issuers, pv, nil, Config{})
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
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{err: &verifier.DenialError{Reason: "denied"}}
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
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"iss": "https://example.com"}}}
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
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"iss": "https://example.com"}}}
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
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"iss": "https://example.com"}}}
	pv := &mockPolicyVerifier{
		permissions: map[string]string{"contents": "read"},
		repos:       []string{"org/repo"},
	}
	ti := &mockTokenIssuer{result: installation.IssueResult{
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

// --- multiple GitHub Apps ---

func TestHandleToken_AppSelection(t *testing.T) {
	ov := &mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"iss": "https://example.com"}}}
	newIssuers := func() (*mockTokenIssuer, *mockTokenIssuer, map[string]tokenIssuer) {
		def := &mockTokenIssuer{result: installation.IssueResult{Token: "ghs_default", ExpiresAt: time.Now().Add(time.Hour)}}
		extra := &mockTokenIssuer{result: installation.IssueResult{Token: "ghs_extra", ExpiresAt: time.Now().Add(time.Hour)}}
		return def, extra, map[string]tokenIssuer{verifier.DefaultApp: def, "extra": extra}
	}

	tests := []struct {
		name      string
		app       string
		wantCode  int
		wantToken string
	}{
		{"app omitted uses default", "", http.StatusOK, "ghs_default"},
		{"explicit default", "default", http.StatusOK, "ghs_default"},
		{"registered app", "extra", http.StatusOK, "ghs_extra"},
		{"unregistered app is denied", "nope", http.StatusForbidden, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def, extra, issuers := newIssuers()
			pv := &mockPolicyVerifier{permissions: map[string]string{"contents": "read"}, repos: []string{"org/repo"}, app: tt.app}
			srv := newTestServerApps(ov, issuers, pv)
			req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer dummy-token")
			rr := httptest.NewRecorder()
			srv.handleToken(rr, req)

			if rr.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d: %s", tt.wantCode, rr.Code, rr.Body)
			}
			if tt.wantCode != http.StatusOK {
				assertCode(t, rr, "FORBIDDEN")
				if strings.Contains(rr.Body.String(), tt.app) {
					t.Errorf("response must not disclose the app name: %s", rr.Body)
				}
				if def.calls != 0 || extra.calls != 0 {
					t.Errorf("no token must be issued for an unregistered app (default=%d extra=%d)", def.calls, extra.calls)
				}
				return
			}
			var resp struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if resp.Token != tt.wantToken {
				t.Errorf("expected token %q, got %q", tt.wantToken, resp.Token)
			}
			wantDef, wantExtra := 0, 0
			if tt.wantToken == "ghs_default" {
				wantDef = 1
			} else {
				wantExtra = 1
			}
			if def.calls != wantDef || extra.calls != wantExtra {
				t.Errorf("issuer calls: default=%d extra=%d, want %d/%d", def.calls, extra.calls, wantDef, wantExtra)
			}
		})
	}
}

func TestHandleTokenRFC7523_UnregisteredApp(t *testing.T) {
	srv := newTestServer(
		&mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"sub": "s"}}},
		&mockTokenIssuer{},
		&mockPolicyVerifier{permissions: map[string]string{"contents": "read"}, app: "nope"},
	)
	rr := httptest.NewRecorder()
	srv.handleToken(rr, formReq(validForm()))
	if rr.Code != http.StatusBadRequest || oauthErr(t, rr) != "invalid_grant" {
		t.Errorf("expected 400 invalid_grant, got %d: %s", rr.Code, rr.Body)
	}
}

func TestConfigValidate_Apps(t *testing.T) {
	base := Config{Audience: "a", Installation: &installation.Client{}, Logger: testLog{}, Verifier: &mockPolicyVerifierShim{}}
	if err := base.Validate(); err != nil {
		t.Fatalf("base config must be valid: %v", err)
	}
	cfg := base
	cfg.Apps = map[string]*installation.Client{"extra": {}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("extra app must be valid: %v", err)
	}
	cfg.Apps = map[string]*installation.Client{verifier.DefaultApp: {}}
	if err := cfg.Validate(); err == nil {
		t.Error("the name \"default\" must be reserved")
	}
	cfg.Apps = map[string]*installation.Client{"extra": nil}
	if err := cfg.Validate(); err == nil {
		t.Error("nil client must be rejected")
	}
}

type mockPolicyVerifierShim struct{}

func (*mockPolicyVerifierShim) Verify(context.Context, map[string]any, string, string) (verifier.Result, error) {
	return verifier.Result{}, nil
}

type emptyAppVerifier struct{}

func (emptyAppVerifier) Verify(context.Context, map[string]any, string, string) (verifier.Result, error) {
	return verifier.Result{Permissions: map[string]string{"contents": "read"}}, nil
}

// A custom Verifier that leaves Result.App empty must be treated as "default".
func TestHandleToken_EmptyAppMeansDefault(t *testing.T) {
	ti := &mockTokenIssuer{result: installation.IssueResult{Token: "ghs_default", ExpiresAt: time.Now().Add(time.Hour)}}
	srv := newTestServer(&mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{}}}, ti, emptyAppVerifier{})
	req := httptest.NewRequest(http.MethodPost, "/token", tokenRequestBody("org/repo", "pol"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)
	if rr.Code != http.StatusOK || ti.calls != 1 {
		t.Errorf("expected 200 via default app, got %d (calls=%d)", rr.Code, ti.calls)
	}
}
