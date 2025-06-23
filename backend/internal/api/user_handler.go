package api

import (
	"encoding/json"
	"net/http"

	"E-Vault/internal/service"
)

// UserHandler holds the dependencies for user-related HTTP handlers
type UserHandler struct {
	service service.UserService
}

// NewUserHandler creates a new UserHandler with its dependencies
func NewUserHandler(svc service.UserService) *UserHandler {
	return &UserHandler{service: svc}
}

// ---Request/Response Structs ---

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	User         interface{} `json:"user"`
	AcessToken   string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// --- Handlers ---

// CreateUser handles the POST /user-service/create endpoint
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Email and password are requried"))
		return
	}

	uuid := r.Header.Get("X-Request-ID") // Example of getting a unique ID per request
	user, accessToken, refreshToken, err := h.service.Create(r.Context(), req.Email, req.Password, uuid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	resp := authResponse{
		User:         user.ToPublic(),
		AcessToken:   accessToken,
		RefreshToken: refreshToken,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// Login handles the POST /user-service/login endpoint
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	uuid := r.Header.Get("X-Request-ID")
	user, accessToken, refreshToken, err := h.service.Login(r.Context(), req.Email, req.Password, uuid)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, FromServiceError(err))
		return
	}

	resp := authResponse{
		User:         user.ToPublic(),
		AcessToken:   accessToken,
		RefreshToken: refreshToken,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ChangePassword is a placeHolder for the PATCH /user-service/change-password endpoint
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Logic for changing password would go here.
	// It requires extracting the user ID from the auth token (middleware)
	writeJSON(w, http.StatusNotImplemented, "Endpoint not implemented yet")
}

// Placeholder handler for routes we haven't fully implemented yet
func (h *UserHandler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, "Endpoint not implemented yet")
}

// --- Helper Functions ---

// writeJSON is a utility for sending JSON responses with a given status code
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
