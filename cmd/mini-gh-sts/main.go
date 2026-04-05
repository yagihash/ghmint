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
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/server"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return 1
	}

	log := logger.New(cfg.Debug)
	ctx := context.Background()

	ov, err := minioidc.New(ctx, "https://"+cfg.Hostname)
	if err != nil {
		log.ErrorContext(ctx, "failed to initialize OIDC verifier", "error", err)
		return 1
	}

	addr := net.JoinHostPort("", strconv.Itoa(cfg.Port))
	srv := server.New(addr, log, ov)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.InfoContext(ctx, "received signal, shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.ErrorContext(ctx, "shutdown error", "error", err)
		}
	}()

	log.InfoContext(ctx, "server starting", "addr", addr)
	if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.ErrorContext(ctx, "server error", "error", err)
		return 1
	}

	log.InfoContext(ctx, "server stopped")
	return 0
}
