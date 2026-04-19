package app

import (
	"context"
	"errors"
	"time"

	"github.com/yagihash/mini-gh-sts/internal/githubapp"
	minioidc "github.com/yagihash/mini-gh-sts/internal/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

// Config holds the configuration for App.
// AppID, Hostname, Logger, Signer, and Verifier are required.
// Timeout fields use built-in defaults when zero.
type Config struct {
	AppID    string
	Hostname string
	Logger   logger.Logger
	Signer   signer.Signer
	Verifier verifier.Verifier

	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
}

// Validate returns an error for each missing required field, joined with errors.Join.
func (c Config) Validate() error {
	var errs []error
	if c.AppID == "" {
		errs = append(errs, errors.New("AppID is required"))
	}
	if c.Hostname == "" {
		errs = append(errs, errors.New("Hostname is required"))
	}
	if c.Logger == nil {
		errs = append(errs, errors.New("Logger is required"))
	}
	if c.Signer == nil {
		errs = append(errs, errors.New("Signer is required"))
	}
	if c.Verifier == nil {
		errs = append(errs, errors.New("Verifier is required"))
	}
	return errors.Join(errs...)
}

// App represents the mini-gh-sts service.
type App struct {
	srv *server
}

// New validates cfg and constructs the service.
func New(cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ov := minioidc.New(cfg.Hostname)
	ti := githubapp.New(cfg.AppID, cfg.Signer)
	srv := newServer(cfg.Logger, ov, ti, cfg.Verifier, cfg)
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
