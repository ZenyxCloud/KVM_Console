package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "query /healthz on LISTEN_ADDR and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel(os.Getenv("LOG_LEVEL"))}))
	cfg, err := LoadConfig(os.Getenv)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		os.Exit(2)
	}
	if len(cfg.AllowedOrigins) == 0 {
		log.Warn("ALLOWED_ORIGINS is empty: console websockets are accepted from any origin")
	}
	if cfg.PVETLS.InsecureSkipVerify {
		log.Warn("PVE_TLS_INSECURE is enabled: Proxmox certificates are not verified")
	}

	srv := NewServer(cfg, log)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.tokens.Purge()
			}
		}
	}()

	errc := make(chan error, 1)
	go func() {
		log.Info("kvm console gateway listening", "addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "", "version", version)
		if cfg.TLSCertFile != "" {
			errc <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errc <- httpServer.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", "error", err.Error())
			os.Exit(1)
		}
	case <-ctx.Done():
		log.Info("shutting down", "sessions", srv.sessions.Active())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}
}

func logLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func runHealthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if os.Getenv("TLS_CERT_FILE") != "" {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: insecureLocalTLS()}
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s/healthz", scheme, addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
