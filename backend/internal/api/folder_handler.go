package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"E-Vault/internal/domain"
	"E-Vault/internal/service"
)

// FolderHandler holds the dependencies for folder-related HTTP handlers.
type FolderHandler struct {
	service service.FolderService
}

// NewFolderHandler creates a new FolderHandler with its dependencies.
func NewFolderHandler(svc service.FolderService) *FolderHandler {
	return &FolderHandler{service: svc}
}

// --- Request/Response Structs with Validation ---

type createFolderRequest struct {
	Name     string `json:"name"`
	ParentID string `json:"parent"` // The ID of the parent folder, or "/" for root.
}

// Validate checks the fields of the createFolderRequest struct based on the rules
// from folder-middleware.ts (min/max length for name).
func (r *createFolderRequest) Validate() error {
	if len(r.Name) < 1 || len(r.Name) > 256 {
		return errors.New("folder name must be between 1 and 256 characters")
	}
	// The parent is optional and defaults to "/", so no further validation is needed here.
	return nil
}

// --- Handlers ---

// GetFolderList handles the GET /folder-service/list endpoint.
func (h *FolderHandler) GetFolderList(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("User ID not found in token"))
		return
	}

	// Parse query parameters from the request URL.
	query := r.URL.Query()
	parent := query.Get("parent")
	if parent == "" {
		parent = "/" // Default to root directory
	}
	sortBy := query.Get("sortBy")
	if sortBy == "" {
		sortBy = "date_desc" // Default sort order
	}

	folders, err := h.service.ListFolders(r.Context(), ownerID, parent, sortBy)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	// If no folders are found, return an empty array instead of null.
	if folders == nil {
		folders = []*domain.Folder{}
	}

	writeJSON(w, http.StatusOK, folders)
}

// CreateFolder handles the POST /folder-service/create endpoint.
func (h *FolderHandler) CreateFolder(w http.ResponseWriter, r *http.Request) {
	// Get the user ID from the context, which was added by the auth middleware.
	ownerID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("User ID not found in token"))
		return
	}

	var req createFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Invalid request body"))
		return
	}

	// Perform validation by calling the Validate method.
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError(err.Error()))
		return
	}

	if req.ParentID == "" {
		req.ParentID = "/" // Default to root if not provided.
	}

	folder, err := h.service.CreateFolder(r.Context(), ownerID, req.Name, req.ParentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	writeJSON(w, http.StatusCreated, folder)
}

// NotImplemented is a placeholder for endpoints that are not yet implemented.
func (h *FolderHandler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, "Endpoint not implemented yet")
}
