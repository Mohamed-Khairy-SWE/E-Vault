package store

import (
	"context"
	"errors"
	"io"

	"E-Vault/internal/domain"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Standard errors returned by the store layer. This allows the service layer
// to handle specific database errors without being coupled to the database implementation
var (
	ErrNotFound = errors.New("requested item not found")
	ErrConflict = errors.New("item already exists")
)

// UserStore defines the interface for user data operations. Any struct that
// implements these methods can be used as a user database by the application
type UserStore interface {
	//Create inserts a new user into the database
	Create(ctx context.Context, user *domain.User) error

	//Update modifies on existing user in the database
	Update(ctx context.Context, user *domain.User) error

	// FindByEmail retrieves a user by their email address. It should return
	// store.ErrNotFound if no user is found
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// FindByID retrieves a user by their unique ID. It should return
	// store.ErrNotFound if no user is found
	FindByID(ctx context.Context, id bson.ObjectID) (*domain.User, error)
}

// ListOptions contains options for listing items, such as sorting and pagination.
type ListOptions struct {
	SortBy    string
	SortOrder int // 1 for ascending, -1 for descending
	Limit     int64
}

// Folder defines the interface for folder data operations
type FolderStore interface {
	Create(ctx context.Context, folder *domain.Folder) error
	GetByID(ctx context.Context, ownerID, folderID bson.ObjectID) (*domain.Folder, error)
	// List retrieves a list of folders filtered by owner and parent.
	List(ctx context.Context, ownerID bson.ObjectID, parentID string, opts ListOptions) ([]*domain.Folder, error)
}

// FileStore defices the interface for file data (GridFS) operations
type FileStore interface {
	Upload(ctx context.Context, name string, metadata domain.FileMetadata, source io.Reader) (*domain.File, error)
	FindByID(ctx context.Context, ownerID, fileID bson.ObjectID) (*domain.File, error)
	Download(ctx context.Context, id bson.ObjectID) (io.ReadCloser, *domain.File, error)
	Delete(ctx context.Context, id bson.ObjectID) error
	// List retrieves a list of files filtered by owner and parent.
	List(ctx context.Context, ownerID bson.ObjectID, parentID string, opts ListOptions) ([]*domain.File, error)
}
