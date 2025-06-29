package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Folder represents a directory in the file system
type Folder struct {
	ID             bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Name           string        `bson:"name" json:"name"`
	ParentID       string        `bson:"parent" json:"parent"`
	OwnerID        bson.ObjectID `bson:"owner" json:"owner"`
	ParentList     []string      `bson:"parentList" json:"parentList"` // Hierarchy of parent IDs
	PersonalFolder bool          `bson:"personalFolder, omitempty" json:"personalFolder,omitempty"`
	Trashed        bool          `bson:"trashed,omitempty" json:"trashed,omitempty"`
	CreatedAt      time.Time     `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time     `bson:"updatedAt" json:"updatedAt"`
}
