package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/yagihash/mini-gh-sts/internal/config"
	"github.com/yagihash/mini-gh-sts/pkg/app"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	"github.com/yagihash/mini-gh-sts/pkg/policystore"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
)

const (
	ExitOK = iota
	ExitError
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return ExitError
	}

	log := logger.New(cfg.Debug)
	ctx := context.Background()

	kmsSigner, err := signer.NewKMSSigner(ctx, cfg.KMSKeyName())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize kms signer: %v\n", err)
		return ExitError
	}

	ps := policystore.NewRepoPolicyStore(cfg.AppID, kmsSigner)
	pv := verifier.New(ps)

	sts, err := app.New(app.Config{
		AppID:    cfg.AppID,
		Hostname: cfg.Hostname,
		Logger:   log,
		Signer:   kmsSigner,
		Verifier: pv,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize app: %v\n", err)
		return ExitError
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.InfoContext(ctx, "received signal, shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := sts.Shutdown(shutdownCtx); err != nil {
			log.ErrorContext(ctx, "shutdown error", "error", err)
		}
	}()

	addr := net.JoinHostPort("", strconv.Itoa(cfg.Port))
	log.InfoContext(ctx, "server starting", "addr", addr)
	if err := sts.Serve(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.ErrorContext(ctx, "server error", "error", err)
		return ExitError
	}

	log.InfoContext(ctx, "server stopped")
	return ExitOK
}
