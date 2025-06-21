package mongo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"E-Vault/internal/config"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// NewClient creates and returns a new MongoDB client based on the provided configuration
// It handles standard connections and connections to AWS DocumentDB using an SSL certificate
func NewClient(ctx context.Context, cfg config.Mongo) (*mongo.Client, error) {
	// Build the MongoDB client options
	clientOptions := options.Client().ApplyURI(cfg.URL)

	// if a path to a DocumentDB certificate bundle is provided, configure TLS.
	if cfg.DocumentDBBundlePath != "" {
		tlsConfig, err := createTLSConfig(cfg.DocumentDBBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config for DocumentDB: %w", err)
		}
		clientOptions.SetTLSConfig(tlsConfig)
	}

	// Connect to MongoDB
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	// Ping the database to verify that the connection is alive and well.
	// This is a crucial step to ensure the application doesn't start with a bad DB connection.
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	return client, nil
}

// createTLSConfig sets up a TLS configuration using a custom CA (Certificate Authority) file.
// This is used to securely connect to services like AWS DocumentDB,
// which may require a specific certificate for SSL/TLS encryption.
func createTLSConfig(caFilePath string) (*tls.Config, error) {
	// Check if the provided CA file path exists on the filesystem.
	// If the file doesn't exist, return an error.
	if _, err := os.Stat(caFilePath); os.IsNotExist(err) {
		return nil, errors.New("DocumentDB CA file not found at path: " + caFilePath)
	}

	// Create a new certificate pool.
	// A cert pool is a set of trusted certificates used to verify the server's identity.
	certs := x509.NewCertPool()

	// Read the contents of the CA certificate file into memory.
	pem, err := os.ReadFile(caFilePath)
	if err != nil {
		// If there's an error reading the file, return it.
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	// SAdd the read certificate (in PEM format) to the cert pool.
	// This tells Go to trust servers signed by this CA.
	certs.AppendCertsFromPEM(pem)

	// Return a tls.Config that includes our custom CA pool.
	// This configuration can be passed to the MongoDB driver for secure connections.
	return &tls.Config{
		RootCAs: certs,
	}, nil
}
