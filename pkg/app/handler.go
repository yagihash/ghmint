package app

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"
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

// handleToken dispatches on Content-Type: application/x-www-form-urlencoded is
// the RFC 7523 token endpoint; anything else goes to the legacy JSON API.
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "application/x-www-form-urlencoded" {
		s.handleTokenRFC7523(w, r)
		return
	}
	s.handleTokenLegacy(w, r)
}

// handleTokenLegacy is the original JSON API (Bearer OIDC token in Authorization header).
func (s *server) handleTokenLegacy(w http.ResponseWriter, r *http.Request) {
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
	if org == "" {
		writeError(w, http.StatusBadRequest, "invalid scope", "BAD_REQUEST")
		return
	}

	result, ierr := s.issue(r.Context(), rawToken, org, req.Scope, req.Policy)
	if ierr != nil {
		switch ierr.kind {
		case issueInvalidAssertion:
			writeError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
		case issueDenied:
			writeError(w, http.StatusForbidden, "token issuance denied by policy", "FORBIDDEN")
		case issuePolicyFailed:
			writeError(w, http.StatusInternalServerError, "policy evaluation failed", "INTERNAL_ERROR")
		default:
			writeError(w, http.StatusInternalServerError, "failed to issue token", "INTERNAL_ERROR")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(struct {
		Token        string            `json:"token"`
		ExpiresAt    string            `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}{
		Token:        result.Token,
		ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
		Permissions:  result.Permissions,
		Repositories: result.Repositories,
	}); err != nil {
		s.logger.WarnContext(r.Context(), "failed to write token response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"code":%q}`, msg, code)
}
