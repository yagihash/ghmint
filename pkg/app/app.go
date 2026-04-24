package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	minioidc "github.com/yagihash/ghmint/internal/oidc"
	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/logger"
	"github.com/yagihash/ghmint/pkg/verifier"
)

// Config holds the configuration for App.
// Audience, Installation, Logger, and Verifier are required.
// Timeout fields use built-in defaults when zero.
// AllowedIssuers is optional: when non-empty, only tokens from listed OIDC issuers are accepted.
// WebhookHandler is optional: when non-nil, POST /webhook is registered with this handler.
type Config struct {
	Audience       string
	AllowedIssuers []string
	Installation   *installation.Client
	Logger         logger.Logger
	Verifier       verifier.Verifier
	WebhookHandler http.Handler

	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
}

// Validate returns an error for each missing required field, joined with errors.Join.
func (c Config) Validate() error {
	var errs []error
	if c.Audience == "" {
		errs = append(errs, errors.New("Audience is required"))
	}
	if c.Installation == nil {
		errs = append(errs, errors.New("Installation is required"))
	}
	if c.Logger == nil {
		errs = append(errs, errors.New("Logger is required"))
	}
	if c.Verifier == nil {
		errs = append(errs, errors.New("Verifier is required"))
	}
	return errors.Join(errs...)
}

// App represents the ghmint service.
type App struct {
	srv *server
}

// New validates cfg and constructs the service.
func New(cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ov := minioidc.New(cfg.Audience, cfg.AllowedIssuers)
	srv := newServer(cfg.Logger, ov, cfg.Installation, cfg.Verifier, cfg.WebhookHandler, cfg)
	return &App{srv: srv}, nil
}

// Serve starts the HTTP server on addr.
func (a *App) Serve(addr string) error {
	return a.srv.Start(addr)
}

// Shutdown gracefully shuts down the server.
func (a *App) Shutdown(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
