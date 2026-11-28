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

	"github.com/yagihash/ghmint/internal/config"
	"github.com/yagihash/ghmint/internal/webhook"
	"github.com/yagihash/ghmint/pkg/app"
	"github.com/yagihash/ghmint/pkg/installation"
	"github.com/yagihash/ghmint/pkg/logger/cloudlogging"
	ghpolicystore "github.com/yagihash/ghmint/pkg/policystore/github"
	kmssigner "github.com/yagihash/ghmint/pkg/signer/kms"
	"github.com/yagihash/ghmint/pkg/verifier"
	regoverifier "github.com/yagihash/ghmint/pkg/verifier/rego"
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

	log := cloudlogging.New(cfg.Debug)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clients := make(map[string]*installation.Client, len(cfg.Apps))
	for _, a := range cfg.Apps {
		signer, err := kmssigner.NewKMSSigner(ctx, a.KMSKeyName())
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize kms signer for app %q: %v\n", a.Name, err)
			return ExitError
		}
		defer func(name string) {
			if err := signer.Close(); err != nil {
				log.WarnContext(ctx, "failed to close kms signer", "app", name, "error", err)
			}
		}(a.Name)
		clients[a.Name] = installation.New(a.AppID, signer)
	}

	// The "default" App fetches policy files and handles webhooks; the other
	// Apps are only used to issue tokens a policy selected with its "app" rule.
	installClient := clients[verifier.DefaultApp]
	delete(clients, verifier.DefaultApp)

	ps := ghpolicystore.NewRepoPolicyStore(installClient)
	pv := regoverifier.New(ps)

	var wh *webhook.Handler
	if cfg.WebhookSecret != "" {
		wh = webhook.NewHandler(ctx, installClient, cfg.WebhookSecret, log, cfg.AppNames())
	}

	appCfg := app.Config{
		Audience:       cfg.Audience,
		AllowedIssuers: cfg.AllowedIssuers,
		Installation:   installClient,
		Apps:           clients,
		Logger:         log,
		Verifier:       pv,
	}
	// Assigning a nil *webhook.Handler directly to the http.Handler field
	// would produce a non-nil interface holding a nil pointer (the classic
	// Go typed-nil gotcha), which app.New would treat as "webhook enabled".
	// Only set the field when wh is genuinely non-nil.
	if wh != nil {
		appCfg.WebhookHandler = wh
	}

	sts, err := app.New(appCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize app: %v\n", err)
		return ExitError
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.InfoContext(ctx, "received signal, shutting down", "signal", sig.String())
		cancel() // stop webhook background goroutines
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := sts.Shutdown(shutdownCtx); err != nil {
			log.ErrorContext(shutdownCtx, "shutdown error", "error", err)
		}
	}()

	addr := net.JoinHostPort("", strconv.Itoa(cfg.Port))
	log.InfoContext(ctx, "server starting", "addr", addr)
	if err := sts.Serve(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.ErrorContext(ctx, "server error", "error", err)
		return ExitError
	}

	if wh != nil {
		wh.Wait()
	}

	log.InfoContext(ctx, "server stopped")
	return ExitOK
}
