package app

import (
	"context"
	"errors"
	"time"

	"github.com/yagihash/mini-gh-sts/pkg/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

// Config は App の設定を保持する。
// AppID・Hostname・Logger・Signer・Verifier は必須フィールド。
// タイムアウト系はゼロ値の場合にデフォルト値が使われる。
type Config struct {
	AppID    string
	Hostname string
	Logger   logger.Logger
	Signer   signer.Signer
	Verifier verifier.Verifier

	// オプション（ゼロ値の場合は以下のデフォルト値を使う）
	// ReadHeaderTimeout: 5s, ReadTimeout: 10s, WriteTimeout: 30s, IdleTimeout: 120s
	// MaxRequestBodyBytes: 1 MiB
	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
}

// Validate は必須フィールドを検証し、複数の不足があれば errors.Join で束ねて返す。
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

// App は mini-gh-sts サービスそのものを表す型。
// OIDC 検証・GitHub App Token 発行・HTTP サーバーを内部で構築して束ねる。
type App struct {
	srv *server
}

// New は Config を検証し、mini-gh-sts サービスを構築する。
// 必須フィールドが欠けている場合は error を返す。
func New(cfg Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	ov := minioidc.New(cfg.Hostname)
	ti := githubapp.New(cfg.AppID, cfg.Signer)
	srv := newServer(cfg.Logger, ov, ti, cfg.Verifier, cfg)
	return &App{srv: srv}, nil
}

// Serve は指定したアドレスで HTTP サーバーを起動する。
func (a *App) Serve(addr string) error {
	return a.srv.Start(addr)
}

// Shutdown はサーバーをグレースフルにシャットダウンする。
func (a *App) Shutdown(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
