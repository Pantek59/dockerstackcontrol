// Command stackctl is a small web application to start, stop and restart
// individual Docker Compose stacks behind per-user permissions.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/docker"
	"github.com/Pantek59/dockerstackcontrol/internal/server"
)

// configFlag overrides the STACKCTL_CONFIG environment variable, which itself
// overrides the default path.
var configFlag = flag.String("config", "", "path to configuration file (default: $STACKCTL_CONFIG, then "+config.DefaultConfigPath+")")

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	path := configPath()

	// Fail fast on an invalid configuration before binding anything.
	holder, err := config.NewHolder(path)
	if err != nil {
		return err
	}
	cfg := holder.Get()
	aud := audit.New(logger)

	logger.Info("configuration loaded",
		"path", path,
		"listen", cfg.Server.Listen,
		"stacks", len(cfg.Stacks),
		"rules", len(cfg.Rules),
		"oidc_issuer", cfg.OIDC.Issuer,
		"cookie_secure", cfg.Server.CookieSecure,
		"session_ttl", cfg.Server.SessionTTL.Std().String(),
		"command_timeout", cfg.Server.CommandTimeout.Std().String(),
		"pull_timeout", cfg.Docker.PullTimeout.Std().String(),
	)

	// OIDC discovery happens here: an unreachable provider aborts startup.
	svc, err := auth.NewService(holder, aud)
	if err != nil {
		return err
	}

	// pull_timeout bounds the slowest commands (pull, up -d), so the write
	// timeout must at least cover that, not only command_timeout.
	dockerTimeout := cfg.Server.CommandTimeout.Std()
	if pull := cfg.Docker.PullTimeout.Std(); pull > dockerTimeout {
		dockerTimeout = pull
	}
	runner := docker.NewExecRunner(cfg.Docker.ComposeBinary,
		cfg.Server.CommandTimeout.Std(), cfg.Docker.PullTimeout.Std())
	srv, err := server.New(holder, runner, svc, aud, logger)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr: cfg.Server.Listen,
		// Write timeout must exceed the longest Docker command timeout, or
		// the response of a slow restart or pull would be cut off.
		WriteTimeout:      dockerTimeout + 30*time.Second,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		Handler:           srv.Handler(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Server.Listen, "external_url", cfg.Server.ExternalURL)
		errCh <- httpServer.ListenAndServe()
	}()

	for {
		select {
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			logger.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				logger.Warn("graceful shutdown incomplete", "err", err)
			}
			return nil
		case <-hup:
			logger.Info("SIGHUP received, reloading configuration")
			if err := holder.Reload(); err != nil {
				aud.ConfigReload(false, path, err)
			} else {
				aud.ConfigReload(true, path, nil)
			}
			// Reload errors never stop the process: the previous config keeps
			// serving and sessions stay valid.
		}
	}
}

func configPath() string {
	path := *configFlag
	if path == "" {
		path = os.Getenv("STACKCTL_CONFIG")
	}
	if path == "" {
		path = config.DefaultConfigPath
	}
	return path
}
