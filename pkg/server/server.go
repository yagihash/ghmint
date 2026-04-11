package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yagihash/mini-gh-sts/pkg/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
)

const (
	maxRequestBodyBytes = 1 * 1024 * 1024 // 1 MiB
)

type oidcVerifier interface {
	Verify(ctx context.Context, rawToken string) (minioidc.Claims, error)
}

type tokenIssuer interface {
	Issue(
		ctx context.Context,
		owner string,
		permissions map[string]string,
		repositories []string,
	) (githubapp.IssueResult, error)
}

type policyVerifier interface {
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (ok bool, permissions map[string]string, repositories []string, err error)
}

type Server struct {
	logger         logger.Logger
	oidcVerifier   oidcVerifier
	tokenIssuer    tokenIssuer
	policyVerifier policyVerifier
	httpServer     *http.Server
}

func New(addr string, log logger.Logger, ov oidcVerifier, ti tokenIssuer, pv policyVerifier) *Server {
	s := &Server{logger: log, oidcVerifier: ov, tokenIssuer: ti, policyVerifier: pv}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /token", s.handleToken)

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.logMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// logMiddleware logs each request with method, path, status code, and duration.
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		ctx := logger.WithRequestID(r.Context(), requestID)
		r = r.WithContext(ctx)

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.logger.InfoContext(ctx, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
}

type tokenRequest struct {
	Scope  string `json:"scope"`
	Policy string `json:"policy"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json", "UNSUPPORTED_MEDIA_TYPE")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

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

	// scope は <org> または <org>/<repo> 形式 — org 部分を取り出す
	org, _, _ := strings.Cut(req.Scope, "/")

	h := sha256.Sum256([]byte(rawToken))
	s.logger.InfoContext(r.Context(), "request", "hashed_token", base64.StdEncoding.EncodeToString(h[:]))

	claims, err := s.oidcVerifier.Verify(r.Context(), rawToken)
	if err != nil {
		s.logger.WarnContext(r.Context(), "oidc verification failed", "error", err)
		writeError(w, http.StatusUnauthorized, "invalid token", "INVALID_TOKEN")
		return
	}

	allowed, permissions, repositories, err := s.policyVerifier.Verify(r.Context(), claims.Raw, req.Scope, req.Policy)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "policy evaluation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "policy evaluation failed", "INTERNAL_ERROR")
		return
	}
	if !allowed {
		s.logger.WarnContext(r.Context(), "policy denied token issuance", "scope", req.Scope, "policy", req.Policy)
		writeError(w, http.StatusForbidden, "token issuance denied by policy", "FORBIDDEN")
		return
	}

	result, err := s.tokenIssuer.Issue(r.Context(), org, permissions, repositories)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to issue github app token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to issue token", "INTERNAL_ERROR")
		return
	}

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
