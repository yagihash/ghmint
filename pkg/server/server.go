package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
)

const (
	maxRequestBodyBytes = 1 * 1024 * 1024 // 1 MiB
)

type oidcVerifier interface {
	Verify(ctx context.Context, rawToken string) (minioidc.Claims, error)
}

type tokenIssuer interface {
	Issue(ctx context.Context, owner string) (string, error)
}

type Server struct {
	logger       logger.Logger
	oidcVerifier oidcVerifier
	tokenIssuer  tokenIssuer
	httpServer   *http.Server
}

func New(addr string, log logger.Logger, ov oidcVerifier, ti tokenIssuer) *Server {
	s := &Server{logger: log, oidcVerifier: ov, tokenIssuer: ti}

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

// logMiddleware logs each request with method, path, status code, and duration.
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		s.logger.InfoContext(r.Context(), "request",
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

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	rawToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || rawToken == "" {
		writeError(w, http.StatusBadRequest, "missing or invalid Authorization header")
		return
	}

	h := sha256.Sum256([]byte(rawToken))
	s.logger.InfoContext(r.Context(), "request", "hashed_token", base64.StdEncoding.EncodeToString(h[:]))

	claims, err := s.oidcVerifier.Verify(r.Context(), rawToken)
	if err != nil {
		s.logger.WarnContext(r.Context(), "oidc verification failed", "error", err)
		writeError(w, http.StatusBadRequest, "invalid token")
		return
	}

	appToken, err := s.tokenIssuer.Issue(r.Context(), claims.RepositoryOwner)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to issue github app token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"token":%q}`, appToken)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
