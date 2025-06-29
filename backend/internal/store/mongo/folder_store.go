package mongo

import (
	"context"
	"errors"

	"E-Vault/internal/domain"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const folderCollection = "folders"

// FolderStore is the MongoDB implementation of the store.FolderStore interface.
type FolderStore struct {
	db *mongo.Database
}

// NewFolderStore creates a new FolderStore.
func NewFolderStore(db *mongo.Database) *FolderStore {
	return &FolderStore{db: db}
}

// Create inserts a new folder document into the folders collection.
func (s *FolderStore) Create(ctx context.Context, folder *domain.Folder) error {
	res, err := s.db.Collection(folderCollection).InsertOne(ctx, folder)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return store.ErrConflict
		}
		return err
	}
	folder.ID = res.InsertedID.(bson.ObjectID)
	return nil
}

// GetByID finds a folder by its ID, ensuring it belongs to the specified owner.
func (s *FolderStore) GetByID(ctx context.Context, ownerID, folderID bson.ObjectID) (*domain.Folder, error) {
	var folder domain.Folder
	filter := bson.M{
		"_id":   folderID,
		"owner": ownerID,
	}

	err := s.db.Collection(folderCollection).FindOne(ctx, filter).Decode(&folder)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &folder, nil
}

// List retrieves a list of folders matching the given criteria.
func (s *FolderStore) List(ctx context.Context, ownerID bson.ObjectID, parentID string, opts store.ListOptions) ([]*domain.Folder, error) {
	// Build the query filter.
	filter := bson.M{
		"owner":   ownerID,
		"parent":  parentID,
		"trashed": bson.M{"$ne": true}, // Exclude trashed folders
	}

	// Set find options for sorting and limiting.
	findOptions := options.Find()
	if opts.SortBy != "" {
		findOptions.SetSort(bson.D{{Key: opts.SortBy, Value: opts.SortOrder}})
	}
	if opts.Limit > 0 {
		findOptions.SetLimit(opts.Limit)
	}

	cursor, err := s.db.Collection(folderCollection).Find(ctx, filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Decode the results into a slice of Folder pointers.
	var folders []*domain.Folder
	if err := cursor.All(ctx, &folders); err != nil {
		return nil, err
	}

	return folders, nil
}
