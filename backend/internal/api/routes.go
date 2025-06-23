package api

import (
	"log"
	"net/http"
)

// method is a helper function to ensure a handler only responds to a specific HTTP method.
func method(m string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			// Using writeJSON helper from user_handler.go
			writeJSON(w, http.StatusMethodNotAllowed, APIError{
				Status:  http.StatusMethodNotAllowed,
				Message: "Method not allowed",
			})
			return
		}
		next(w, r)
	}
}

// RegisterRoutes sets up all the application's routes on the given ServeMux.
func RegisterRoutes(mux *http.ServeMux, userHandler *UserHandler, logger *log.Logger) {
	// For now, we'll create a simple placeholder auth middleware.
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Println("Auth middleware placeholder: checking token...")
			// Real auth logic would go here. For now, we'll just pass through.
			next.ServeHTTP(w, r)
		})
	}

	// --- User Service Routes ---
	mux.HandleFunc("/user-service/create", method("POST", userHandler.CreateUser))
	mux.HandleFunc("/user-service/login", method("POST", userHandler.Login))

	// Routes requiring authentication
	mux.Handle("/user-service/user", authMiddleware(method("GET", userHandler.NotImplemented)))
	mux.Handle("/user-service/user-detailed", authMiddleware(method("GET", userHandler.NotImplemented)))
	mux.Handle("/user-service/change-password", authMiddleware(method("PATCH", userHandler.ChangePassword)))
	mux.Handle("/user-service/resend-verify-email", authMiddleware(method("PATCH", userHandler.NotImplemented)))
	mux.Handle("/user-service/logout", authMiddleware(http.HandlerFunc(userHandler.NotImplemented)))
	mux.Handle("/user-service/logout-all", authMiddleware(http.HandlerFunc(userHandler.NotImplemented)))

	// Public routes
	mux.HandleFunc("/user-service/verify-email", method("PATCH", userHandler.NotImplemented))
	mux.HandleFunc("/user-service/reset-password", method("PATCH", userHandler.NotImplemented))
	mux.HandleFunc("/user-service/send-password-reset", method("PATCH", userHandler.NotImplemented))
	mux.HandleFunc("/user-service/get-token", method("POST", userHandler.NotImplemented)) // Uses authRefresh middleware

	logger.Println("Registered user routes")
}

// We have to add this custom PATCH handler because the default ServeMux doesn't support it.
// This is a workaround for sticking to the standard library.
// We can wrap our main mux with this to add PATCH support.
func NewPatchRouter(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			// Find a handler that matches the path.
			handler, pattern := mux.Handler(r)

			// If a handler is found for the path (even if it's for a different method),
			// serve the request. Our `method` helper inside the handler will
			// then correctly apply method-specific logic.
			if pattern != "" {
				handler.ServeHTTP(w, r)
				return
			}
		}
		// For all other methods, use the default mux behavior.
		mux.ServeHTTP(w, r)
	})
}
