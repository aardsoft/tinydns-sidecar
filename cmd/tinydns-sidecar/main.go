package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/aardsoft/tinydns-sidecar/internal/api"
	"github.com/aardsoft/tinydns-sidecar/internal/config"
	"github.com/aardsoft/tinydns-sidecar/internal/storage"
)

func main() {
	// Structured JSON logging for Kubernetes log aggregation.
	slogOpts := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey && len(groups) == 0 {
				return slog.String("_msg", a.Value.String())
			}
			return a
		},
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, slogOpts)))

	cfgPath := flag.String("config", os.Getenv("TINYDNS_CONFIG"), "path to config file (env: TINYDNS_CONFIG)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("loading config", "error", err)
		os.Exit(1)
	}

	store, err := storage.NewFileStore(cfg.Storage.ZonesDir, cfg.Storage.RebuildCommand)
	if err != nil {
		slog.Error("initialising storage", "error", err)
		os.Exit(1)
	}

	srv := api.NewServer(cfg, store)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
