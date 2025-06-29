package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"E-Vault/internal/service"
)

// --- Regular Expressions for Validation ---

// regex for email validation.
var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

// --- Request/Response Structs with Validation ---

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate checks the fields of the createUserRequest struct.
func (r *createUserRequest) Validate() error {
	if len(r.Email) < 3 || len(r.Email) > 320 {
		return errors.New("email must be between 3 and 320 characters")
	}
	if !emailRegex.MatchString(r.Email) {
		return errors.New("email is not a valid format")
	}
	if len(r.Password) < 6 || len(r.Password) > 256 {
		return errors.New("password must be between 6 and 256 characters")
	}
	return nil
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate checks the fields of the loginRequest struct.
func (r *loginRequest) Validate() error {
	if r.Email == "" {
		return errors.New("email is required")
	}
	if r.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

type authResponse struct {
	User         interface{} `json:"user"`
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// Validate checks the fields of the changePasswordRequest struct.
func (r *changePasswordRequest) Validate() error {
	if len(r.OldPassword) < 6 || len(r.OldPassword) > 256 {
		return errors.New("old password must be between 6 and 256 characters")
	}
	if len(r.NewPassword) < 6 || len(r.NewPassword) > 256 {
		return errors.New("new password must be between 6 and 256 characters")
	}
	return nil
}

// --- User Handler ---

// UserHandler holds the dependencies for user-related HTTP handlers.
type UserHandler struct {
	service service.UserService
}

// NewUserHandler creates a new UserHandler with its dependencies.
func NewUserHandler(svc service.UserService) *UserHandler {
	return &UserHandler{service: svc}
}

// CreateUser handles the POST /user-service/create endpoint.
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	// Perform validation by calling the Validate method.
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError(err.Error()))
		return
	}

	user, accessToken, refreshToken, err := h.service.Create(r.Context(), req.Email, req.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	resp := authResponse{
		User:         user.ToPublic(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// Login handles the POST /user-service/login endpoint.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	// Perform validation.
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError(err.Error()))
		return
	}

	user, accessToken, refreshToken, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		// Note: The service layer returns a generic "invalid credentials" error,
		// which we map to a 401 Unauthorized status here.
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("Invalid email or password"))
		return
	}

	resp := authResponse{
		User:         user.ToPublic(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ChangePassword handles the PATCH /user-service/change-password endpoint.
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	// Get the user ID from the context, which was added by the auth middleware.
	userID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("User ID not found in token"))
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	// Perform validation.
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError(err.Error()))
		return
	}

	accessToken, refreshToken, err := h.service.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, FromServiceError(err))
		return
	}

	resp := authResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	writeJSON(w, http.StatusOK, resp)
}

// NotImplemented is a placeholder for endpoints that are not yet implemented.
func (h *UserHandler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, "Endpoint not implemented yet")
}

// --- Helper Functions ---

// writeJSON is a utility for sending JSON responses with a given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
