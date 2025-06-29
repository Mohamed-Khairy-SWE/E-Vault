package mongo

import (
	"context"
	"errors"
	"io"
	"time"

	"E-Vault/internal/domain"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// FileStore is the MongoDB GridFS implementation of store.FileStore.
type FileStore struct {
	bucket *mongo.GridFSBucket
}

// NewFileStore initializes the GridFS bucket from the v2 mongo.Database.
func NewFileStore(db *mongo.Database) *FileStore {
	bucket := db.GridFSBucket(options.GridFSBucket()) // use default options
	return &FileStore{bucket: bucket}
}

// Upload streams a file to GridFS, setting its filename and metadata.
func (s *FileStore) Upload(ctx context.Context, name string, metadata domain.FileMetadata, source io.Reader) (*domain.File, error) {
	// Convert our domain.FileMetadata to a BSON document to be stored by GridFS.
	metaDoc, err := bson.Marshal(metadata)
	if err != nil {
		return nil, err
	}

	opts := options.GridFSUpload().SetMetadata(metaDoc)
	fileID, err := s.bucket.UploadFromStream(ctx, name, source, opts)
	if err != nil {
		return nil, err
	}

	// After uploading, we construct the File object to return it.
	return &domain.File{
		ID:         fileID,
		Filename:   name,
		UploadDate: time.Now(),
		Metadata:   metadata,
		// Length and ChunkSize are populated by GridFS but we can get them if needed.
	}, nil
}

// FindByID finds a file's metadata from the 'fs.files' collection.
// It does not download the file content.
func (s *FileStore) FindByID(ctx context.Context, ownerID, fileID bson.ObjectID) (*domain.File, error) {
	filter := bson.M{
		"_id":            fileID,
		"metadata.owner": ownerID,
	}

	res := s.bucket.GetFilesCollection().FindOne(ctx, filter)
	if err := res.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}

	var file domain.File
	if err := res.Decode(&file); err != nil {
		return nil, err
	}

	return &file, nil
}

// List retrieves a list of files matching the given criteria.
func (s *FileStore) List(ctx context.Context, ownerID bson.ObjectID, parentID string, opts store.ListOptions) ([]*domain.File, error) {
	// Build the query filter for files.
	filter := bson.M{
		"metadata.owner":   ownerID,
		"metadata.parent":  parentID,
		"metadata.trashed": bson.M{"$ne": true}, // Exclude trashed files
	}

	findOptions := options.Find()
	if opts.SortBy != "" {
		findOptions.SetSort(bson.D{{Key: opts.SortBy, Value: opts.SortOrder}})
	}

	if opts.SortBy == "filename" {
		findOptions.SetCollation(&options.Collation{Locale: "en", Strength: 2})
	}
	if opts.Limit > 0 {
		findOptions.SetLimit(opts.Limit)
	}

	cursor, err := s.bucket.GetFilesCollection().Find(ctx, filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var files []*domain.File
	if err := cursor.All(ctx, &files); err != nil {
		return nil, err
	}

	return files, nil
}

// Download opens a stream to download a file's content from GridFS.
// It also returns the file's metadata.
func (s *FileStore) Download(ctx context.Context, id bson.ObjectID) (io.ReadCloser, *domain.File, error) {
	stream, err := s.bucket.OpenDownloadStream(ctx, id)
	if err != nil {
		// Check if the error is because the file doesn't exist.
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil, store.ErrNotFound
		}
		return nil, nil, err
	}

	gridfsFile := stream.GetFile()

	var metadata domain.FileMetadata
	if err := bson.Unmarshal(gridfsFile.Metadata, &metadata); err != nil {
		return nil, nil, err
	}

	file := &domain.File{
		ID:         gridfsFile.ID.(bson.ObjectID),
		Length:     gridfsFile.Length,
		ChunkSize:  gridfsFile.ChunkSize,
		UploadDate: gridfsFile.UploadDate,
		Filename:   gridfsFile.Name,
		Metadata:   metadata,
	}

	return stream, file, nil
}

// Delete removes a file and all its associated chunks from GridFS.
func (s *FileStore) Delete(ctx context.Context, id bson.ObjectID) error {
	err := s.bucket.Delete(ctx, id)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return store.ErrNotFound
	}
	return err
}
