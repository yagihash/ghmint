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
	"github.com/yagihash/mini-gh-sts/pkg/githubapp"
	"github.com/yagihash/mini-gh-sts/pkg/logger"
	minioidc "github.com/yagihash/mini-gh-sts/pkg/oidc"
	"github.com/yagihash/mini-gh-sts/pkg/policystore"
	"github.com/yagihash/mini-gh-sts/pkg/server"
	"github.com/yagihash/mini-gh-sts/pkg/signer"
	"github.com/yagihash/mini-gh-sts/pkg/verifier"
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

	ov := minioidc.New("https://" + cfg.Hostname)

	ti, err := githubapp.New(cfg.AppID, cfg.PrivateKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize github app token issuer: %v\n", err)
		return 1
	}

	rs, err := signer.NewRSASignerFromFile(cfg.PrivateKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize rsa signer: %v\n", err)
		return 1
	}

	ac := githubapp.NewAppClient(cfg.AppID, rs)
	ps := policystore.NewRepoPolicyStore(ac)
	pv := verifier.New(ps)

	addr := net.JoinHostPort("", strconv.Itoa(cfg.Port))
	srv := server.New(addr, log, ov, ti, pv)

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
