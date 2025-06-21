package config

import (
	"os"
	"strconv"
	"time"
)

// Auth contains configuration related to authentication and JWTs
type Auth struct {
	AccessKey     string        // JWT signing key for access tokens
	RefreshKey    string        // JWT signing key for refresh tokens
	CookieKey     string        // Key for encrypting cookies
	AccessKeyTTL  time.Duration // Time-to-live for access tokens
	RefreshKeyTTL time.Duration // Time-to-live for refresh tokens
}

// Mongo contains configuration for the MongoDB connection
type Mongo struct {
	URL                  string // MongoDB connection URI
	DocumentDBBundlePath string // It stores the path to the certificate file. An empty string means don't use it.
}

// Storage contains configuration for file storage
type Storage struct {
	Type        string // Type of Storage ("fs" or "s3")
	FSDirectory string // Base directory for local filesystem storage
	S3ID        string // AWS S3 Access Key ID
	S3Key       string // AWS S3 Secret Access Key
	S3Bucket    string // AWS S3 Bucket name
}

// Email contains configuration for sending emails
type Email struct {
	VerificationEnabled bool
	APIKey              string // API key for the email service (e.g., SendGrid)
	Host                string // SMTP host
	Port                int    // SMTP port
	Address             string // The "From" email address
}

// HTTP contains configuration for the HTTP server
type HTTP struct {
	Port          string // Port for the server to listen on
	URL           string // Public-facing URL of the service
	SecureCookies bool   // Whether to set the "Secure" flag on cookies
	KeyPath       string // Path to SSL key file for HTTPS
	CertPath      string // Path to SSL certification file for HTTPs
}

// Config is the top-level struct holding all application configuration
type Config struct {
	Auth                   Auth
	Mongo                  Mongo
	Storage                Storage
	Email                  Email
	HTTP                   HTTP
	MasterEncryptionKey    string // Master key for encrypting user data
	CreateAccountBlocked   bool   // If true, disables new account creation
	VideoThumbnailsEnabled bool   // If true, enables video thumbnail generation
	TempDir                string // Temporary directory for file processing
}

// The Load function reads configuration from environment variables and returns a populated Config struct
//
//	It uses helper functions to read specific types and provide default values
func Load() (*Config, error) {
	emailPort, err := getenvInt("EMAIL_PORT", 587)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		MasterEncryptionKey:    getenvStr("KEY", ""),
		CreateAccountBlocked:   getenvBool("BLOCK_CREATE_ACCOUNT", false),
		TempDir:                getenvStr("TEMP_DIRECTORY", "/tmp"),
		VideoThumbnailsEnabled: getenvBool("VIDEO_THUMBNAILS_ENABLED", false),

		Auth: Auth{
			AccessKey:     getenvStr("PASSWORD_ACCESS", ""),
			RefreshKey:    getenvStr("PASSWORD_REFRESH", ""),
			CookieKey:     getenvStr("PASSWORD_COOKIE", ""),
			AccessKeyTTL:  20 * time.Minute,
			RefreshKeyTTL: 30 * 24 * time.Hour,
		},
		Mongo: Mongo{
			URL:                  getenvStr("MONGODB_URL", "mongodb://localhost:27017"),
			DocumentDBBundlePath: getenvStr("DOCUMENT_DB_BUNDLE_PATH", ""),
		},
		Storage: Storage{
			Type:        getenvStr("DB_TYPE", "fs"), // "fs" or "s3"
			FSDirectory: getenvStr("FS_DIRECTORY", "./uploads"),
			S3ID:        getenvStr("S3_ID", ""),
			S3Key:       getenvStr("S3_KEY", ""),
			S3Bucket:    getenvStr("S3_BUCKET", ""),
		},
		Email: Email{
			VerificationEnabled: getenvBool("EMAIL_VERIFICATION", false),
			APIKey:              getenvStr("EMAIL_API_KEY", ""),
			Host:                getenvStr("EMAIL_HOST", ""),
			Port:                emailPort,
			Address:             getenvStr("EMAIL_ADDRESS", ""),
		},
		HTTP: HTTP{
			Port:          getenvStr("PORT", ":8080"),
			URL:           getenvStr("URL", "http://localhost:8080"),
			SecureCookies: getenvBool("SECURE_COOKIES", false),
			KeyPath:       getenvStr("HTTPS_KEY_PATH", ""),
			CertPath:      getenvStr("HTTPS_CRT_PATH", ""),
		},
	}
	return cfg, nil
}

// -------Helper Functions----------

// getenvStr retrieves a string environment variable or returns a default
func getenvStr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// getenvBool retrieves a boolean environment variable or returns a default value
func getenvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return fallback
}

// getenvInt retrieves an integer environment variable or returns a default value.
func getenvInt(key string, fallback int) (int, error) {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(value); err == nil {
			return i, nil
		} else {
			return 0, err
		}
	}
	return fallback, nil
}
