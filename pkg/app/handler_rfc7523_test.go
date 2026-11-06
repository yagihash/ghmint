package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	minioidc "github.com/yagihash/ghmint/internal/oidc"
	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/verifier"
)

func formReq(v url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	return req
}

func validForm() url.Values {
	return url.Values{
		"grant_type": {grantTypeJWTBearer},
		"assertion":  {"oidc.jwt"},
		"scope":      {"org/repo:pol"},
	}
}

func oauthErr(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct{ Error string }
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return b.Error
}

func TestHandleTokenRFC7523_Success(t *testing.T) {
	srv := newTestServer(
		&mockOIDCVerifier{claims: minioidc.Claims{Raw: map[string]any{"sub": "s"}}},
		&mockTokenIssuer{result: installation.IssueResult{Token: "ghs_x", ExpiresAt: time.Now().Add(time.Hour), Permissions: map[string]string{"contents": "read"}, Repositories: []string{"org/repo"}}},
		&mockPolicyVerifier{permissions: map[string]string{"contents": "read"}},
	)
	rr := httptest.NewRecorder()
	srv.handleToken(rr, formReq(validForm()))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Error("missing no-store/no-cache headers")
	}
	var b struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.AccessToken != "ghs_x" || b.TokenType != "Bearer" || b.ExpiresIn < 3500 || b.ExpiresIn > 3600 {
		t.Errorf("unexpected body: %+v", b)
	}
}

func TestHandleTokenRFC7523_RequestErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{"missing grant_type", func(v url.Values) { v.Del("grant_type") }, "invalid_request"},
		{"wrong grant_type", func(v url.Values) { v.Set("grant_type", "client_credentials") }, "unsupported_grant_type"},
		{"missing assertion", func(v url.Values) { v.Del("assertion") }, "invalid_request"},
		{"missing scope", func(v url.Values) { v.Del("scope") }, "invalid_scope"},
		{"multiple scope tokens", func(v url.Values) { v.Set("scope", "org:a b:c") }, "invalid_scope"},
		{"empty org", func(v url.Values) { v.Set("scope", "/repo:pol") }, "invalid_scope"},
		{"no policy separator", func(v url.Values) { v.Set("scope", "org/repo") }, "invalid_scope"},
		{"empty policy", func(v url.Values) { v.Set("scope", "org:") }, "invalid_scope"},
		{"empty repo", func(v url.Values) { v.Set("scope", "org/:pol") }, "invalid_scope"},
		{"duplicate param", func(v url.Values) { v.Add("assertion", "other") }, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(nil, nil, nil)
			v := validForm()
			tt.mutate(v)
			rr := httptest.NewRecorder()
			srv.handleToken(rr, formReq(v))
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
			if got := oauthErr(t, rr); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestHandleTokenRFC7523_QueryParamsIgnored(t *testing.T) {
	srv := newTestServer(nil, nil, nil)
	req := formReq(url.Values{})
	req.URL.RawQuery = validForm().Encode()
	rr := httptest.NewRecorder()
	srv.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest || oauthErr(t, rr) != "invalid_request" {
		t.Errorf("query params must not be accepted: %d %s", rr.Code, rr.Body)
	}
}

func TestHandleTokenRFC7523_Failures(t *testing.T) {
	ok := &mockOIDCVerifier{}
	tests := []struct {
		name   string
		srv    *server
		status int
		want   string
	}{
		{"invalid assertion", newTestServer(&mockOIDCVerifier{err: errors.New("bad")}, nil, nil), 400, "invalid_grant"},
		{"policy denied", newTestServer(ok, nil, &mockPolicyVerifier{err: &verifier.DenialError{Reason: "no"}}), 400, "invalid_grant"},
		{"policy internal", newTestServer(ok, nil, &mockPolicyVerifier{err: errors.New("boom")}), 500, "server_error"},
		{"issue failed", newTestServer(ok, &mockTokenIssuer{err: errors.New("gh")}, &mockPolicyVerifier{}), 500, "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tt.srv.handleToken(rr, formReq(validForm()))
			if rr.Code != tt.status || oauthErr(t, rr) != tt.want {
				t.Errorf("got %d %s", rr.Code, rr.Body)
			}
		})
	}
}

func TestParseScopeToken(t *testing.T) {
	tests := []struct{ in, scope, policy string }{
		{"org:pol", "org", "pol"},
		{"org/repo:pol", "org/repo", "pol"},
		{"org/repo:a:b", "org/repo", "a:b"},
	}
	for _, tt := range tests {
		sc, p, ok := parseScopeToken(tt.in)
		if !ok || sc != tt.scope || p != tt.policy {
			t.Errorf("%q: got %q %q %v", tt.in, sc, p, ok)
		}
	}
}
