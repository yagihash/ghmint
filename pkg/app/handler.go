package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
}

type tokenRequest struct {
	Scope  string `json:"scope"`
	Policy string `json:"policy"`
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxRequestBodyBytes)

	rawToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || rawToken == "" {
		writeError(w, http.StatusBadRequest, "missing or invalid Authorization header", "BAD_REQUEST")
		return
	}

	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if req.Scope == "" {
		writeError(w, http.StatusBadRequest, "scope is required", "MISSING_SCOPE")
		return
	}
	if req.Policy == "" {
		writeError(w, http.StatusBadRequest, "policy is required", "MISSING_POLICY")
		return
	}

	org, _, _ := strings.Cut(req.Scope, "/")

	claims, err := s.oidcVerifier.Verify(r.Context(), rawToken)
	if err != nil {
		s.logger.WarnContext(r.Context(), "oidc verification failed", "error", err)
		writeError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
		return
	}

	permissions, repositories, err := s.policyVerifier.Verify(r.Context(), claims.Raw, req.Scope, req.Policy)
	if err != nil {
		var policyErr *verifier.DenialError
		if errors.As(err, &policyErr) {
			s.logger.WarnContext(r.Context(), "policy denied token issuance", "scope", req.Scope, "policy", req.Policy, "reason", policyErr.Reason)
			writeError(w, http.StatusForbidden, "token issuance denied by policy", "FORBIDDEN")
		} else {
			s.logger.ErrorContext(r.Context(), "policy evaluation failed", "error", err)
			writeError(w, http.StatusInternalServerError, "policy evaluation failed", "INTERNAL_ERROR")
		}
		return
	}

	result, err := s.tokenIssuer.Issue(r.Context(), org, permissions, repositories)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to issue github app token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to issue token", "INTERNAL_ERROR")
		return
	}

	h := sha256.Sum256([]byte(result.Token))
	s.logger.InfoContext(r.Context(), "request", "hashed_token", base64.StdEncoding.EncodeToString(h[:]))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Token        string            `json:"token"`
		ExpiresAt    string            `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}{
		Token:        result.Token,
		ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
		Permissions:  result.Permissions,
		Repositories: result.Repositories,
	})
}

func writeError(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"code":%q}`, msg, code)
}
