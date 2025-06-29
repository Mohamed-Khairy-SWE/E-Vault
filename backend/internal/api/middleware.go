package api

import (
	"context"
	"net/http"

	"E-Vault/internal/platform/crypto"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// CtxKey is a custom type for context keys to avoid collisions.
type CtxKey string

const (
	// UserIDKey is the key for storing the user's ID in the request context.
	UserIDKey CtxKey = "userID"
	// EmailKey is the key for storing the user's email in the request context.
	EmailKey CtxKey = "email"
)

// AuthMiddleware is a struct that holds the dependencies for our auth middleware.
type AuthMiddleware struct {
	tokenSvc  crypto.TokenGenerator
	userStore store.UserStore
}

// NewAuthMiddleware creates a new AuthMiddleware.
func NewAuthMiddleware(tokenSvc crypto.TokenGenerator, userStore store.UserStore) *AuthMiddleware {
	return &AuthMiddleware{
		tokenSvc:  tokenSvc,
		userStore: userStore,
	}
}

// RequireAuth is the main authentication middleware. It checks for a valid access
// token in the cookies. If found, it adds the user's ID and email to the request context.
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the "access-token" cookie.
		cookie, err := r.Cookie("access-token")
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("Missing authentication token"))
			return
		}

		// Verify the token.
		claims, err := m.tokenSvc.Verify(cookie.Value)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("Invalid authentication token"))
			return
		}

		// Add user information to the request context for downstream handlers.
		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, EmailKey, claims.Email)

		// Serve the next handler with the modified context.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserIDFromContext is a helper function to safely retrieve the user ID from the context.
func GetUserIDFromContext(ctx context.Context) (bson.ObjectID, bool) {
	userID, ok := ctx.Value(UserIDKey).(bson.ObjectID)
	return userID, ok
}
