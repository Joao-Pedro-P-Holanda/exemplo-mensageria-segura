package main

import (
	"context"
	"errors"
	"log/slog"
	"mensageria_segura/internal/database"
	"mensageria_segura/internal/hub"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"github.com/rs/cors"
)

func main() {
	// Initialize beautiful logging with colors and full date
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "2006-01-02 15:04:05",
		NoColor:    false,
	}))
	slog.SetDefault(logger)

	if _, err := database.InitInMemory(); err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	h := hub.NewHub(serverCtx)
	go h.Run()

	c := NewController(serverCtx, h)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", c.HandleWS)
	mux.HandleFunc("/key-exchange", c.HandleKeyExchange)

	port := ":8080"
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
	}).Handler(mux)

	server := &http.Server{
		Addr:         port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Listen for syscall signals for a process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with a grace period of 30 seconds
		shutdownCtx, cancel := context.WithTimeout(serverCtx, 30*time.Second)
		defer cancel()

		go func() {
			<-shutdownCtx.Done()
			if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
				slog.Error("graceful shutdown timed out.. forcing exit.")
				os.Exit(1)
			}
		}()

		// Trigger graceful shutdown
		slog.Info("Shutting down server...")
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			slog.Error("server shutdown failed", "error", err)
			os.Exit(1)
		}
		serverStopCtx()
	}()

	slog.Info("WebSocket server starting", "port", port)
	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
	slog.Info("Server stopped gracefully")
}
