package crypto

import (
	"fmt"
	"time"

	"E-Vault/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// TokenGenerator defines the interface for creating JWTs
type TokenGenerator interface {
	NewPair(user *domain.User) (accessToken, refreshToken string, err error)
}

// JWTGenerator is a concrete implementation of TokenGenerator using JWT
type JWTGenerator struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewJWTGenerator creates a new JWTGenerator
// It requires the secrets and time-to-live (TTL) durations
func NewJWTGenerator(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *JWTGenerator {
	return &JWTGenerator{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// Claims represents the standard JWT claims for the application
type Claims struct {
	UserID bson.ObjectID `json:"userId"`
	Email  string        `json:"email"`
	jwt.RegisteredClaims
}

// NewPair generates a new access and refresh token for the given user
func (g *JWTGenerator) NewPair(user *domain.User) (string, string, error) {
	// Create Access Token
	accessExp := time.Now().Add(g.accessTTL)
	accessClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(g.accessSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create Refresh Token
	refreshExp := time.Now().Add(g.refreshTTL)
	refreshClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(g.refreshSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedAccessToken, signedRefreshToken, nil
}
