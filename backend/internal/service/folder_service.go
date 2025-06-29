package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"E-Vault/internal/domain"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FolderService defines the interface for folder-related business logic.
// We define an interface to allow for mock implementations in tests.
type FolderService interface {
	CreateFolder(ctx context.Context, ownerID bson.ObjectID, name, parentID string) (*domain.Folder, error)
	ListFolders(ctx context.Context, ownerID bson.ObjectID, parentID, sortBy string) ([]*domain.Folder, error)
}

// folderService is the concrete implementation of the FolderService interface.
type folderService struct {
	folderStore store.FolderStore
	fileStore   store.FileStore
}

// NewFolderService creates a new instance of the folder service.
func NewFolderService(folderStore store.FolderStore, fileStore store.FileStore) FolderService {
	return &folderService{
		folderStore: folderStore,
		fileStore:   fileStore,
	}
}

// parseFolderSort is a helper to convert an API sort string into database-compatible fields.
// This is the Go equivalent of your `sortBySwitchFolder.ts`.
func parseFolderSort(sortBy string) (field string, order int) {
	// Default sort order
	field = "createdAt"
	order = -1 // Descending

	switch sortBy {
	case "date_asc":
		field = "createdAt"
		order = 1
	case "date_desc":
		field = "createdAt"
		order = -1
	case "alp_asc":
		field = "name"
		order = 1
	case "alp_desc":
		field = "name"
		order = -1
	}
	return field, order
}

// ListFolders retrieves a list of folders for a given parent directory.
func (s *folderService) ListFolders(ctx context.Context, ownerID bson.ObjectID, parentID, sortBy string) ([]*domain.Folder, error) {
	sortField, sortOrder := parseFolderSort(sortBy)

	opts := store.ListOptions{
		SortBy:    sortField,
		SortOrder: sortOrder,
	}

	folders, err := s.folderStore.List(ctx, ownerID, parentID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list folders from store: %w", err)
	}

	return folders, nil
}

// CreateFolder handles the business logic for creating a new folder.
func (s *folderService) CreateFolder(ctx context.Context, ownerID bson.ObjectID, name, parentID string) (*domain.Folder, error) {
	if name == "" {
		return nil, errors.New("folder name cannot be empty")
	}

	parentList := []string{}
	if parentID != "/" {
		pID, err := bson.ObjectIDFromHex(parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent ID format: %w", err)
		}

		parentFolder, err := s.folderStore.GetByID(ctx, ownerID, pID)
		if err != nil {
			return nil, fmt.Errorf("could not find parent folder: %w", err)
		}
		parentList = append(parentFolder.ParentList, parentFolder.ID.Hex())
	} else {
		parentList = []string{"/"}
	}

	now := time.Now()
	folder := &domain.Folder{
		Name:       name,
		ParentID:   parentID,
		OwnerID:    ownerID,
		ParentList: parentList,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.folderStore.Create(ctx, folder); err != nil {
		return nil, fmt.Errorf("failed to create folder in store: %w", err)
	}

	return folder, nil
}
