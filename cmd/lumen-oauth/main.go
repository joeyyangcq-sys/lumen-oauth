package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"github.com/joey/lumen-oauth/internal/bootstrap"
	"github.com/joey/lumen-oauth/internal/config"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}
	app, err := bootstrap.New(cfg)
	if err != nil {
		panic(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil && err != context.Canceled {
		panic(err)
	}
}
