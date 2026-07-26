package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/webcyber/webcyber/internal/control"
	"github.com/webcyber/webcyber/internal/scan"
)

const defaultControlAddress = "127.0.0.1:7071"

type daemonConfig struct {
	address    string
	token      string
	allowLocal bool
	manager    control.ManagerConfig
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	os.Exit(run(logger))
}

func run(logger *slog.Logger) int {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid control service configuration", "error", err)
		return 2
	}

	manager, err := control.NewManager(scan.NewDefault(), config.manager)
	if err != nil {
		logger.Error("could not initialize scan manager", "error", err)
		return 2
	}
	defer manager.Close()

	api, err := control.NewAPI(control.APIConfig{
		Manager:    manager,
		Token:      config.token,
		AllowLocal: config.allowLocal,
		Version:    scan.Version,
	})
	if err != nil {
		logger.Error("could not initialize control API", "error", err)
		return 2
	}

	listener, err := net.Listen("tcp", config.address)
	if err != nil {
		logger.Error("could not bind control service", "address", config.address, "error", err)
		return 1
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()
	logger.Info("WebCyber control service listening",
		"address", listener.Addr().String(),
		"localPaths", config.allowLocal,
		"maxConcurrency", config.manager.MaxConcurrency,
	)

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("control service stopped unexpectedly", "error", err)
			return 1
		}
	case <-signalContext.Done():
		manager.CancelAll()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("graceful HTTP shutdown failed", "error", err)
			_ = server.Close()
		}
	}
	return 0
}

func loadConfig(getenv func(string) string) (daemonConfig, error) {
	defaults := control.DefaultManagerConfig()
	config := daemonConfig{
		address:    strings.TrimSpace(getenv("WEBCYBER_CONTROL_ADDR")),
		token:      strings.TrimSpace(getenv("WEBCYBER_CONTROL_TOKEN")),
		allowLocal: strings.EqualFold(strings.TrimSpace(getenv("WEBCYBER_ALLOW_LOCAL")), "true"),
		manager:    defaults,
	}
	if config.address == "" {
		config.address = defaultControlAddress
	}
	if len(config.token) < 32 {
		return daemonConfig{}, errors.New("WEBCYBER_CONTROL_TOKEN must contain at least 32 bytes")
	}
	if len(strings.Fields(config.token)) != 1 {
		return daemonConfig{}, errors.New("WEBCYBER_CONTROL_TOKEN must not contain whitespace")
	}

	var err error
	if config.manager.MaxConcurrency, err = positiveEnv(getenv, "WEBCYBER_MAX_CONCURRENCY", defaults.MaxConcurrency); err != nil {
		return daemonConfig{}, err
	}
	if config.manager.MaxJobs, err = positiveEnv(getenv, "WEBCYBER_MAX_JOBS", defaults.MaxJobs); err != nil {
		return daemonConfig{}, err
	}
	if config.manager.MaxRetained, err = positiveEnv(getenv, "WEBCYBER_MAX_RETAINED", defaults.MaxRetained); err != nil {
		return daemonConfig{}, err
	}
	if config.manager.MaxJobs < config.manager.MaxConcurrency {
		return daemonConfig{}, fmt.Errorf("WEBCYBER_MAX_JOBS must be at least WEBCYBER_MAX_CONCURRENCY")
	}
	return config, nil
}

func positiveEnv(getenv func(string) string, name string, fallback int) (int, error) {
	value := strings.TrimSpace(getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}
