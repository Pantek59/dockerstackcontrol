// Command stackctl is a small web application to start, stop and restart
// individual Docker Compose stacks behind per-user permissions.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
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
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return nil
		case <-hup:
			logger.Info("SIGHUP received, reloading configuration")
			err := holder.Reload()
			aud.ConfigReload(err == nil, path, err)
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

var hup = make(chan os.Signal, 1)
