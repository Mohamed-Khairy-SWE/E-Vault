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
	"E-Vault/internal/service"
	"E-Vault/internal/store/mongo"
)

// main is the entry point for the application.
func main() {
	if err := run(); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}

// run initializes and starts the HTTP server.
func run() error {
	// =========================================================================
	// Configuration
	//
	// Load configuration from environment variables.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup structured logger.
	logger := log.New(os.Stdout, "DRIVE-CLONE | ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile)
	logger.Println("Configuration loaded")

	// =========================================================================
	// Database Connection
	//
	// Create a context with a timeout for the connection attempt.
	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to MongoDB using the configuration.
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
	// Initialize Dependencies (Dependency Injection)
	//
	// This is where we "wire" our application together.

	// Initialize the MongoDB user store.
	userStore := mongo.NewUserStore(dbClient.Database("drive_clone")) // Assuming 'drive_clone' as DB name

	// Initialize the user service, injecting the store and config.
	userService := service.NewUserService(userStore, *cfg)

	// Initialize the HTTP handlers, injecting the service.
	userHandler := api.NewUserHandler(userService)

	logger.Println("Dependencies initialized")

	// =========================================================================
	// HTTP Server Setup
	mux := http.NewServeMux()

	// Register all our API routes.
	api.RegisterRoutes(mux, userHandler, logger)

	// Add a root handler for health checks.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "API is running.")
	})

	// This is where you would add middleware like CORS, Helmet, etc.
	// For example: `handler = corsMiddleware(handler)`
	// Our custom router adds PATCH support to the standard library's mux.
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

	// Start the primary server (either HTTP or HTTPS).
	go func() {
		logger.Printf("Server starting on %s", server.Addr)
		// Check if SSL is configured.
		if cfg.HTTP.KeyPath != "" && cfg.HTTP.CertPath != "" {
			// Start HTTPS server
			shutdownErr <- server.ListenAndServeTLS(cfg.HTTP.CertPath, cfg.HTTP.KeyPath)
		} else {
			// Start HTTP server
			shutdownErr <- server.ListenAndServe()
		}
	}()

	// Listen for OS signals for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-shutdownErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		logger.Printf("Shutdown signal received: %s", sig)
	}

	// Attempt a graceful shutdown.
	ctx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Println("Server shut down gracefully")
	return nil
}
