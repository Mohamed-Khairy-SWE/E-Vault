package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"E-Vault/internal/api"
	"E-Vault/internal/config"
	"E-Vault/internal/platform/crypto"
	"E-Vault/internal/platform/email"
	"E-Vault/internal/service"
	"E-Vault/internal/store/mongo"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}

func run() error {
	// =========================================================================
	// Configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := log.New(os.Stdout, "E-Vault | ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	logger.Println("Configuration loaded")

	// =========================================================================
	// Database Connection
	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbClient, err := mongo.NewClient(dbCtx, cfg.Mongo)
	if err != nil {
		return fmt.Errorf("could not connect to database: %w", err)
	}
	defer func() {
		if err := dbClient.Disconnect(context.Background()); err != nil {
			logger.Printf("Error disconnecting from DB: %v", err)
		}
	}()
	logger.Println("Database connection established")

	// =========================================================================
	// Initialize Dependencies

	// Initialize the platform services (crypto).
	passwordManager := crypto.NewBcryptManager(0) // Use default cost
	tokenGenerator := crypto.NewJWTGenerator(
		cfg.Auth.AccessKey,
		cfg.Auth.RefreshKey,
		cfg.Auth.AccessKeyTTL,
		cfg.Auth.RefreshKeyTTL,
	)
	emailService := email.NewSMTPEmailService(cfg.Email, cfg.HTTP.URL)
	logger.Println("Platform services initialized")

	// Initialize the MongoDB user store.
	userStore := mongo.NewUserStore(dbClient.Database("drive_clone"))

	// Initialize the user service, injecting all its dependencies.
	userService := service.NewUserService(userStore, *cfg, tokenGenerator, passwordManager, emailService)

	// Initialize the HTTP handlers.
	userHandler := api.NewUserHandler(userService)

	logger.Println("Dependencies initialized")

	// =========================================================================
	// HTTP Server Setup
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, userHandler, logger)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "API is running.")
	})

	handler := api.NewPatchRouter(mux)

	server := &http.Server{
		Addr:         cfg.HTTP.Port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// =========================================================================
	// Start Server & Graceful Shutdown
	shutdownErr := make(chan error)
	go func() {
		logger.Printf("Server starting on %s", server.Addr)
		if cfg.HTTP.KeyPath != "" && cfg.HTTP.CertPath != "" {
			shutdownErr <- server.ListenAndServeTLS(cfg.HTTP.CertPath, cfg.HTTP.KeyPath)
		} else {
			shutdownErr <- server.ListenAndServe()
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-shutdownErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		logger.Printf("Shutdown signal received: %s", sig)
	}

	ctx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Println("Server shut down gracefully")
	return nil
}
