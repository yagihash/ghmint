package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- helpers ---

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKeyJWK(key *rsa.PublicKey, kid string) map[string]any {
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e, uint32(key.E))
	i := 0
	for i < len(e)-1 && e[i] == 0 {
		i++
	}
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e[i:]),
	}
}

// newTestOIDCServer starts a minimal OIDC provider serving discovery and JWKS endpoints.
func newTestOIDCServer(t *testing.T, key *rsa.PublicKey) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + srv.Listener.Addr().String()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/jwks",
				"subject_types_supported":               []string{"public"},
				"response_types_supported":              []string{"id_token"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{
				"keys": []any{publicKeyJWK(key, "test-key")},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, issuer, audience string) string {
	t.Helper()
	now := time.Now()
	headerJSON, _ := json.Marshal(map[string]string{"typ": "JWT", "alg": "RS256", "kid": "test-key"})
	payloadJSON, _ := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": "test-subject",
		"aud": audience,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := h + "." + p
	hash := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// rawJWT builds a syntactically valid but unsigned JWT (signature is literal "sig").
func rawJWT(alg, iss string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"` + alg + `"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `"}`))
	return h + "." + p + ".sig"
}

// --- parseUnsafe ---

func TestParseUnsafe_Valid(t *testing.T) {
	header, claims, err := parseUnsafe(rawJWT("RS256", "https://issuer.example"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %q", header.Alg)
	}
	if claims.Iss != "https://issuer.example" {
		t.Errorf("expected iss=https://issuer.example, got %q", claims.Iss)
	}
}

func TestParseUnsafe_NotThreeParts(t *testing.T) {
	if _, _, err := parseUnsafe("a.b"); err == nil {
		t.Fatal("expected error for 2-part token")
	}
}

func TestParseUnsafe_BadBase64Header(t *testing.T) {
	if _, _, err := parseUnsafe("!!!.payload.sig"); err == nil {
		t.Fatal("expected error for invalid base64 header")
	}
}

func TestParseUnsafe_BadHeaderJSON(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	if _, _, err := parseUnsafe(h + ".payload.sig"); err == nil {
		t.Fatal("expected error for invalid header JSON")
	}
}

// --- Verify ---

func TestVerify_AlgNone(t *testing.T) {
	v := New("aud", nil)
	if _, err := v.Verify(context.Background(), rawJWT("none", "https://issuer.example")); err == nil {
		t.Fatal("expected error for alg=none")
	}
}

func TestVerify_IssuerNotInAllowlist(t *testing.T) {
	v := New("aud", []string{"https://allowed.example"})
	if _, err := v.Verify(context.Background(), rawJWT("RS256", "https://evil.example")); err == nil {
		t.Fatal("expected error for issuer not in allowlist")
	}
}

func TestVerify_AllowlistNilPermitsAny(t *testing.T) {
	key := mustGenerateRSAKey(t)
	srv := newTestOIDCServer(t, &key.PublicKey)
	issuer := "http://" + srv.Listener.Addr().String()

	v := New(issuer, nil)
	token := signTestJWT(t, key, issuer, issuer)
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("unexpected error with nil allowlist: %v", err)
	}
}

func TestVerify_Success(t *testing.T) {
	key := mustGenerateRSAKey(t)
	srv := newTestOIDCServer(t, &key.PublicKey)
	issuer := "http://" + srv.Listener.Addr().String()

	v := New(issuer, []string{issuer})
	token := signTestJWT(t, key, issuer, issuer)
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Raw["iss"] != issuer {
		t.Errorf("expected iss=%q in claims, got %v", issuer, claims.Raw["iss"])
	}
}

func TestVerify_ProviderCached(t *testing.T) {
	key := mustGenerateRSAKey(t)
	srv := newTestOIDCServer(t, &key.PublicKey)
	issuer := "http://" + srv.Listener.Addr().String()

	v := New(issuer, nil)
	token := signTestJWT(t, key, issuer, issuer)
	for range 2 {
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	v.mu.Lock()
	n := len(v.providers)
	v.mu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 cached provider, got %d", n)
	}
}
