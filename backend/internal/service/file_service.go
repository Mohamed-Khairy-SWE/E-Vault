package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"E-Vault/internal/domain"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FileService defines the interface for file-related business logic.
type FileService interface {
	UploadFile(ctx context.Context, ownerID bson.ObjectID, parentID, filename string, source io.Reader, size int64) (*domain.File, error)
	ListFiles(ctx context.Context, ownerID bson.ObjectID, parentID, sortBy string, limit int64) ([]*domain.File, error)
}

// fileService is the concrete implementation of the FileService interface.
type fileService struct {
	fileStore   store.FileStore
	folderStore store.FolderStore
}

// NewFileService creates a new instance of the file service.
func NewFileService(fileStore store.FileStore, folderStore store.FolderStore) FileService {
	return &fileService{
		fileStore:   fileStore,
		folderStore: folderStore,
	}
}

// parseFileSort is a helper to convert an API sort string into database-compatible fields.
// This is the Go equivalent of your `sortBySwitch.ts`.
func parseFileSort(sortBy string) (field string, order int) {
	// Default sort order
	field = "uploadDate"
	order = -1 // Descending

	switch sortBy {
	case "date_asc":
		field = "uploadDate"
		order = 1
	case "date_desc":
		field = "uploadDate"
		order = -1
	case "alp_asc":
		field = "filename"
		order = 1
	case "alp_desc":
		field = "filename"
		order = -1
	}
	return field, order
}

// ListFiles retrieves a list of files for a given parent directory.
func (s *fileService) ListFiles(ctx context.Context, ownerID bson.ObjectID, parentID, sortBy string, limit int64) ([]*domain.File, error) {
	sortField, sortOrder := parseFileSort(sortBy)

	opts := store.ListOptions{
		SortBy:    sortField,
		SortOrder: sortOrder,
		Limit:     limit,
	}

	files, err := s.fileStore.List(ctx, ownerID, parentID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list files from store: %w", err)
	}

	return files, nil
}

// UploadFile handles the business logic for uploading a new file.
func (s *fileService) UploadFile(ctx context.Context, ownerID bson.ObjectID, parentID, filename string, source io.Reader, size int64) (*domain.File, error) {
	if filename == "" {
		return nil, errors.New("filename cannot be empty")
	}

	var parentList []string
	if parentID != "/" {
		pID, err := bson.ObjectIDFromHex(parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID format: %w", err)
		}

		parentFolder, err := s.folderStore.GetByID(ctx, ownerID, pID)
		if err != nil {
			return nil, fmt.Errorf("could not find parent folder for upload: %w", err)
		}
		parentList = append(parentFolder.ParentList, parentFolder.ID.Hex())
	} else {
		parentList = []string{"/"}
	}

	// Replicate the original schema's storage of the parent list as a JSON-like string.
	parentListStr := fmt.Sprintf(`["%s"]`, strings.Join(parentList, `","`))

	metadata := domain.FileMetadata{
		Owner:      ownerID,
		ParentID:   parentID,
		ParentList: parentListStr,
		Size:       size,
		// These fields would be populated by more advanced logic.
		IV:      []byte("placeholder_iv"),
		IsVideo: false,
	}

	file, err := s.fileStore.Upload(ctx, filename, metadata, source)
	if err != nil {
		return nil, fmt.Errorf("failed to upload file to store: %w", err)
	}

	return file, nil
}
