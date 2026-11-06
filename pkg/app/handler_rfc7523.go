package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// handleTokenRFC7523 implements the token endpoint of RFC 6749 §3.2 using the
// JWT Bearer authorization grant of RFC 7523 §2.1.
//
//	grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
//	assertion  = <OIDC ID Token>
//	scope      = <org>[/<repo>]:<policy>  (single scope-token)
//
// The client is not authenticated (RFC 7523 §2.1 allows this); the assertion
// itself is the credential.
func (s *server) handleTokenRFC7523(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}
	// Only body parameters are honoured (RFC 6749 §3.2: parameters are sent in the body).
	form := r.PostForm

	// RFC 6749 §3.2: parameters MUST NOT be included more than once.
	for k, v := range form {
		if len(v) > 1 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "duplicate parameter: "+k)
			return
		}
	}

	grantType := form.Get("grant_type")
	if grantType == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	}
	if grantType != grantTypeJWTBearer {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only "+grantTypeJWTBearer+" is supported")
		return
	}

	assertion := form.Get("assertion")
	if assertion == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "assertion is required")
		return
	}

	rawScope := form.Get("scope")
	if rawScope == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope is required")
		return
	}
	scope, policy, ok := parseScopeToken(rawScope)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope must be <org>[/<repo>]:<policy>")
		return
	}
	org, _, _ := strings.Cut(scope, "/")

	result, ierr := s.issue(r.Context(), assertion, org, scope, policy)
	if ierr != nil {
		switch ierr.kind {
		case issueInvalidAssertion:
			// RFC 7523 §3.1: an invalid assertion is reported as invalid_grant.
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid assertion")
		case issueDenied:
			// Fail-closed: policy absence/denial/misconfiguration are indistinguishable to the client.
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "token issuance denied by policy")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	expiresIn := int64(time.Until(result.ExpiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	if err := json.NewEncoder(w).Encode(struct {
		AccessToken  string            `json:"access_token"`
		TokenType    string            `json:"token_type"`
		ExpiresIn    int64             `json:"expires_in"`
		ExpiresAt    string            `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}{
		AccessToken:  result.Token,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		ExpiresAt:    result.ExpiresAt.Format(time.RFC3339),
		Permissions:  result.Permissions,
		Repositories: result.Repositories,
	}); err != nil {
		s.logger.WarnContext(r.Context(), "failed to write token response", "error", err)
	}
}

// writeOAuthError writes an RFC 6749 §5.2 error response.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	b, _ := json.Marshal(struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
	}{code, desc})
	w.Write(b)
}

// parseScopeToken splits "<org>[/<repo>]:<policy>" at the last colon.
// It rejects whitespace (multiple scope-tokens) and empty components.
func parseScopeToken(raw string) (scope, policy string, ok bool) {
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", "", false
	}
	i := strings.LastIndex(raw, ":")
	if i < 0 {
		return "", "", false
	}
	scope, policy = raw[:i], raw[i+1:]
	org, repo, hasRepo := strings.Cut(scope, "/")
	if org == "" || policy == "" || (hasRepo && (repo == "" || strings.Contains(repo, "/"))) {
		return "", "", false
	}
	return scope, policy, true
}
