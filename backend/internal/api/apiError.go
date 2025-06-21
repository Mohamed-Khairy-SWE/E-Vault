package api

import (
	"errors"
	"net/http"

	"E-Vault/internal/store"
)

// APIError represents a structured error response to be sent to the client
// It implements the standard `error` interface.
type APIError struct {
	//Status is the HTTP status code that corresponds to this error.
	Status int `json:"status"`
	// Message is the user-friendly error message
	Message string `json:"message"`
}

// Error implements the error interface, allowing APIError to be used as a standard error
func (e *APIError) Error() string {
	return e.Message
}

// --- Error Constructors ---

// NewBadRequestError creates an error representing a 400 Bad Request
// Useful for validation failures or malformed requests
func NewBadRequestError(message string) *APIError {
	return &APIError{
		Status:  http.StatusBadRequest,
		Message: message,
	}
}

// NewUnauthorizedError creates an error representing a 401 Unauthorized
// Useful when authentication is required and has failed or has not yet been provided
func NewUnauthorizedError(message string) *APIError {
	return &APIError{
		Status:  http.StatusUnauthorized,
		Message: message,
	}
}

// NewForbiddenError creates an error representing a 403 Forbidden
// Useful when the user is authenticated but not authorized to perform an action
func NewForbiddenError(message string) *APIError {
	return &APIError{
		Status:  http.StatusForbidden,
		Message: message,
	}
}

// NewNotFoundError creates an error representing a 404 Not Found.
func NewNotFoundError(message string) *APIError {
	return &APIError{
		Status:  http.StatusNotFound,
		Message: message,
	}
}

// NewConflictError creates an error representing a 409 Conflict
// Useful for cases like trying to create a resource that already exists (e.g., duplicate email)
func NewConflictError(message string) *APIError {
	return &APIError{
		Status:  http.StatusConflict,
		Message: message,
	}
}

// NewInternalServerError creates an error representing a 500 Internal Server Error
// This should be used for unexpected server-side issues
func NewInternalServerError() *APIError {
	return &APIError{
		Status:  http.StatusInternalServerError,
		Message: "An unexpected error occured. Please try again later.",
	}
}

// --- Error Translation ---

// FromServiceError translates errors from the service/store layer into specific
// APIError types. This allows the HTTP handlers to be decoupled from the underlying
// store implementation details
func FromServiceError(err error) *APIError {
	if errors.Is(err, store.ErrNotFound) {
		return NewNotFoundError("The requested resource could not be found")
	}
	if errors.Is(err, store.ErrConflict) {
		return NewConflictError("A conflict occurred with the current state of the resource")
	}

	// For any other untranslatable error, we return a generic internal server error
	// to avoid leaking implementation details to the client
	return NewInternalServerError()
}
