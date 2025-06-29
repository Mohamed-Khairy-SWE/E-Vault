package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// FileMetadata represents the nested metadata object within a File document
// This contains all the application-specific information about the file
type FileMetadata struct {
	Owner        bson.ObjectID `bson:"owner" json:"owner"`
	ParentID     string        `bson:"parent" json:"parent"`         // The ID of the direct parent folder
	ParentList   string        `bson:"parentList" json:"parentList"` // JSON string of the parent folder hierarchy
	HasThumbnail bool          `bson:"hasThumbnail" json:"hasThumbnail"`
	IsVideo      bool          `bson:"isVideo" json:"isVideo"`
	ThumbnailID  bson.ObjectID `bson:"thumbnailID,omitempty" json:"thumbnailID,omitempty"`
	Size         int64         `bson:"size" json:"size"`                             // Duplicates the 'Length' field for easier access
	IV           []byte        `bson:"IV" json:"-"`                                  // Initialization Vector for AES encryption, Omitted from JSON
	LinkType     string        `bson:"linkType,omitempty" json:"linkType,omitempty"` // e.g. "public"
	Link         string        `bson:"link,omitempty" json:"link,omitempty"`         // The unique string for the public link.
	FilePath     string        `bson:"filePath,omitempty" json:"-"`                  // Path for local filesystem storage. Omitted from JSON.
	S3ID         string        `bson:"s3ID,omitempty" json:"-"`                      // ID for S3 object storage. Omitted from JSON.
	PersonalFile bool          `bson:"personalFile,omitempty" json:"personalFile,omitempty"`
	Trashed      bool          `bson:"trashed,omitempty" json:"trashed,omitempty"`
}

// File represents a file's metadata stored in the 'fs.files' collection,
// conforming to the GridFS specification.
type File struct {
	ID         bson.ObjectID `bson:"_id" json:"id"`
	Length     int64         `bson:"length" json:"length"`
	ChunkSize  int32         `bson:"chunkSize" json:"chunkSize"`
	UploadDate time.Time     `bson:"uploadDate" json:"uploadDate"`
	Filename   string        `bson:"filename" json:"filename"`
	Metadata   FileMetadata  `bson:"metadata" json:"metadata"`
}
