package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/yagihash/mini-gh-sts/internal/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/internal/oidc"
)

const (
	defaultReadHeaderTimeout   = 5 * time.Second
	defaultReadTimeout         = 10 * time.Second
	defaultWriteTimeout        = 30 * time.Second
	defaultIdleTimeout         = 120 * time.Second
	defaultMaxRequestBodyBytes = 1 * 1024 * 1024
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
	Verify(ctx context.Context, claims map[string]interface{}, scope, policy string) (permissions map[string]string, repositories []string, err error)
}

type server struct {
	logger              logger.Logger
	oidcVerifier        oidcVerifier
	tokenIssuer         tokenIssuer
	policyVerifier      policyVerifier
	maxRequestBodyBytes int64
	httpServer          *http.Server
}

func newServer(log logger.Logger, ov oidcVerifier, ti tokenIssuer, pv policyVerifier, cfg Config) *server {
	s := &server{
		logger:         log,
		oidcVerifier:   ov,
		tokenIssuer:    ti,
		policyVerifier: pv,
	}

	s.maxRequestBodyBytes = cfg.MaxRequestBodyBytes
	if s.maxRequestBodyBytes == 0 {
		s.maxRequestBodyBytes = defaultMaxRequestBodyBytes
	}

	readHeaderTimeout := cfg.ReadHeaderTimeout
	if readHeaderTimeout == 0 {
		readHeaderTimeout = defaultReadHeaderTimeout
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = defaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = defaultWriteTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /token", s.handleToken)

	s.httpServer = &http.Server{
		Handler:           s.logMiddleware(mux),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	return s
}

func (s *server) Start(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

func (s *server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *server) logMiddleware(next http.Handler) http.Handler {
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

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
