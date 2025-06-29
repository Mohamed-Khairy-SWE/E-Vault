package api

import (
	"errors"
	"net/http"
	"strconv"

	"E-Vault/internal/domain"
	"E-Vault/internal/service"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FileHandler holds the dependencies for file-related HTTP handlers.
type FileHandler struct {
	service service.FileService
}

// NewFileHandler creates a new FileHandler with its dependencies.
func NewFileHandler(svc service.FileService) *FileHandler {
	return &FileHandler{service: svc}
}

// --- Request/Response Structs ---

type renameFileRequest struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (r *renameFileRequest) Validate() error {
	if _, err := bson.ObjectIDFromHex(r.ID); err != nil {
		return errors.New("id must be a valid object ID string")
	}
	if len(r.Title) < 1 || len(r.Title) > 256 {
		return errors.New("title must be between 1 and 256 characters")
	}
	return nil
}

// --- Handlers ---

// GetList handles the GET /file-service/list endpoint.
func (h *FileHandler) GetList(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("User ID not found in token"))
		return
	}

	// Parse query parameters.
	query := r.URL.Query()
	parent := query.Get("parent")
	if parent == "" {
		parent = "/"
	}
	sortBy := query.Get("sortBy")
	if sortBy == "" {
		sortBy = "date_desc"
	}
	limit, _ := strconv.ParseInt(query.Get("limit"), 10, 64)
	if limit <= 0 {
		limit = 50 // Default limit
	}

	files, err := h.service.ListFiles(r.Context(), ownerID, parent, sortBy, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	// Ensure we return an empty array `[]` instead of `null` if no files are found.
	if files == nil {
		files = []*domain.File{}
	}

	writeJSON(w, http.StatusOK, files)
}

// UploadFile handles the POST /file-service/upload endpoint.
func (h *FileHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	ownerID, ok := GetUserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, NewUnauthorizedError("User ID not found in token"))
		return
	}

	const maxUploadSize = 1 << 30 // 1 GB
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Failed to parse multipart form: "+err.Error()))
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("File upload is required: 'file' field not found"))
		return
	}
	defer file.Close()

	parentID := r.FormValue("parentID")
	if parentID == "" {
		parentID = "/"
	}
	filename := handler.Filename
	if len(filename) == 0 || len(filename) >= 256 {
		writeJSON(w, http.StatusBadRequest, NewBadRequestError("Filename is required and must be less than 256 characters"))
		return
	}

	uploadedFile, err := h.service.UploadFile(r.Context(), ownerID, parentID, filename, file, handler.Size)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, FromServiceError(err))
		return
	}

	writeJSON(w, http.StatusCreated, uploadedFile)
}

// DownloadFile handles the GET /file-service/download/:id endpoint.
func (h *FileHandler) DownloadFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusNotImplemented, "Download endpoint not fully implemented yet.")
}

// NotImplemented is a placeholder for endpoints that are not yet implemented.
func (h *FileHandler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, "Endpoint not implemented yet")
}
