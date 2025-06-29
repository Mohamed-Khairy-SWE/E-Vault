package api

import (
	"log"
	"net/http"
)

// method is a helper that wraps an http.HandlerFunc and ensures it only responds
// to a specific HTTP method.
func method(m string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			writeJSON(w, http.StatusMethodNotAllowed, APIError{Status: http.StatusMethodNotAllowed, Message: "Method not allowed"})
			return
		}
		next(w, r)
	}
}

// RegisterRoutes sets up all the application's routes on the given ServeMux.
func RegisterRoutes(
	mux *http.ServeMux,
	userHandler *UserHandler,
	folderHandler *FolderHandler,
	fileHandler *FileHandler,
	auth *AuthMiddleware,
	logger *log.Logger,
) {
	// --- Public User Routes ---
	mux.HandleFunc("/user-service/create", method("POST", userHandler.CreateUser))
	mux.HandleFunc("/user-service/login", method("POST", userHandler.Login))
	mux.HandleFunc("/user-service/verify-email", method("PATCH", userHandler.NotImplemented))
	mux.HandleFunc("/user-service/reset-password", method("PATCH", userHandler.NotImplemented))
	mux.HandleFunc("/user-service/send-password-reset", method("PATCH", userHandler.NotImplemented))

	// --- Authenticated User Routes ---
	mux.Handle("/user-service/user", auth.RequireAuth(method("GET", userHandler.NotImplemented)))
	mux.Handle("/user-service/user-detailed", auth.RequireAuth(method("GET", userHandler.NotImplemented)))
	mux.Handle("/user-service/logout", auth.RequireAuth(method("POST", userHandler.NotImplemented)))
	mux.Handle("/user-service/logout-all", auth.RequireAuth(method("POST", userHandler.NotImplemented)))
	mux.Handle("/user-service/get-token", auth.RequireAuth(method("POST", userHandler.NotImplemented)))
	mux.Handle("/user-service/change-password", auth.RequireAuth(method("PATCH", userHandler.ChangePassword)))
	mux.Handle("/user-service/resend-verify-email", auth.RequireAuth(method("PATCH", userHandler.NotImplemented)))

	// --- Authenticated Folder Routes ---
	mux.Handle("/folder-service/create", auth.RequireAuth(method("POST", folderHandler.CreateFolder)))
	mux.Handle("/folder-service/upload", auth.RequireAuth(method("POST", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/list", auth.RequireAuth(method("GET", folderHandler.GetFolderList)))
	mux.Handle("/folder-service/info/", auth.RequireAuth(method("GET", folderHandler.NotImplemented))) // Note: Path params require manual parsing
	mux.Handle("/folder-service/move-folder-list", auth.RequireAuth(method("GET", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/download-zip", auth.RequireAuth(method("GET", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/rename", auth.RequireAuth(method("PATCH", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/move", auth.RequireAuth(method("PATCH", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/trash", auth.RequireAuth(method("PATCH", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/restore", auth.RequireAuth(method("PATCH", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/remove", auth.RequireAuth(method("DELETE", folderHandler.NotImplemented)))
	mux.Handle("/folder-service/remove-all", auth.RequireAuth(method("DELETE", folderHandler.NotImplemented)))

	// --- Authenticated File Routes ---
	mux.Handle("/file-service/upload", auth.RequireAuth(method("POST", fileHandler.UploadFile)))
	mux.Handle("/file-service/list", auth.RequireAuth(method("GET", fileHandler.GetList)))
	mux.Handle("/file-service/download/", auth.RequireAuth(method("GET", fileHandler.DownloadFile)))
	mux.Handle("/file-service/thumbnail/", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/full-thumbnail/", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/info/", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/quick-list", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/stream-video/", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/suggested-list", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/download/access-token-stream-video", auth.RequireAuth(method("GET", fileHandler.NotImplemented)))
	mux.Handle("/file-service/make-public/", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/make-one/", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/rename", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/move", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/move-multi", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/trash", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/trash-multi", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/restore", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/restore-multi", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/remove-link/", auth.RequireAuth(method("PATCH", fileHandler.NotImplemented)))
	mux.Handle("/file-service/remove/", auth.RequireAuth(method("DELETE", fileHandler.NotImplemented)))
	mux.Handle("/file-service/remove-multi", auth.RequireAuth(method("DELETE", fileHandler.NotImplemented)))
	mux.Handle("/file-service/remove/token-video/", auth.RequireAuth(method("DELETE", fileHandler.NotImplemented)))
	mux.Handle("/file-service/remove-stream-video-token", auth.RequireAuth(method("DELETE", fileHandler.NotImplemented)))

	// --- Public File Routes ---
	mux.HandleFunc("/file-service/public/download/", method("GET", fileHandler.NotImplemented))
	mux.HandleFunc("/file-service/public/info/", method("GET", fileHandler.NotImplemented))

	logger.Println("Registered all application routes with auth middleware")
}

// NewPatchRouter adds PATCH method support to the standard library's mux.
// This wrapper should be used around the main mux to enable PATCH requests.
func NewPatchRouter(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The standard library's ServeMux doesn't route PATCH requests by default.
		// This workaround checks if the method is PATCH. If it is, it finds a handler
		// for the registered path (regardless of method) and lets our `method()` helper
		// inside the handler do the final check. This is a common pattern for
		// working with the standard library mux.
		if r.Method == "PATCH" {
			handler, pattern := mux.Handler(r)
			if pattern != "" { // A handler is registered for this path pattern
				handler.ServeHTTP(w, r)
				return
			}
		}
		// For all other methods, or if no handler is found, use default behavior.
		mux.ServeHTTP(w, r)
	})
}
