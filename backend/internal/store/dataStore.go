package store

import (
	"context"
	"errors"

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
