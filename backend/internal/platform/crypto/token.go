package crypto

import (
	"fmt"
	"time"

	"E-Vault/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// TokenGenerator defines the interface for creating and validating JWTs.
type TokenGenerator interface {
	NewPair(user *domain.User) (accessToken, refreshToken string, err error)
	Verify(tokenString string) (*Claims, error)
}

// JWTGenerator is a concrete implementation of TokenGenerator using JWT.
type JWTGenerator struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

// NewJWTGenerator creates a new JWTGenerator.
func NewJWTGenerator(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *JWTGenerator {
	return &JWTGenerator{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// Claims represents the standard JWT claims for our application.
type Claims struct {
	UserID bson.ObjectID `json:"userId"`
	Email  string        `json:"email"`
	jwt.RegisteredClaims
}

// NewPair generates a new access and refresh token for the given user.
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

// Verify parses a token string, validates its signature and expiration, and returns the claims.
// This single method can verify both access and refresh tokens, as it tries both secret keys.
func (g *JWTGenerator) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}

	// The key function checks the signing method and provides the correct secret key.
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is what we expect.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// We don't know if it's an access or refresh token, so we'll try the access secret first.
		return g.accessSecret, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)

	// If the token failed validation with the access secret, try the refresh secret.
	if err != nil {
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return g.refreshSecret, nil
		}
		token, err = jwt.ParseWithClaims(tokenString, claims, keyFunc)
		// If it still fails, the token is invalid.
		if err != nil {
			return nil, fmt.Errorf("invalid token: %w", err)
		}
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
