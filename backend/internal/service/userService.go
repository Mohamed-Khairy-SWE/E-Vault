package service

import (
	"context"
	"errors"
	"time"

	"E-Vault/internal/config"
	"E-Vault/internal/domain"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// These are placeholder types for services I will create later
// This allows me to define the UserService's dependencies without
// having to implement the crypto and email logic right now
type TokenGenerator interface {
	NewPair(ctx context.Context, user domain.User, uuid string) (accessToken, refreshToken string, err error)
}

type PasswordManager interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}

// UserServie defines the interface for user-related business logic
type UserService interface {
	Create(ctx context.Context, email, password, uuid string) (*domain.User, string, string, error)
	Login(ctx context.Context, email, password, uuid string) (*domain.User, string, string, error)
	//ChangePassword(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword, uuid string) (string, string, error)
}

// userService is the concrete implementation of the UserService interface
// It holds the necessary dependencies for its methods
type userService struct {
	userStore store.UserStore
	cfg       config.Config
	// tokenSvc TokenGenerator // I will uncomment these when i build them
	// passSvc  PasswordManager
}

func NewUserService(userStore store.UserStore, cfg config.Config /* , ts TokenGenerator , ps PasswordManager*/) UserService {
	return &userService{
		userStore: userStore,
		cfg:       cfg,
		// tokenSvc: ts,
		// passSvc: ps,
	}
}

// Create handles the business logic for registering a new user
func (s *userService) Create(ctx context.Context, email, password, uuid string) (*domain.User, string, string, error) {
	if s.cfg.CreateAccountBlocked {
		return nil, "", "", errors.New("account creation is disabled")
	}

	// Check if user already exists
	if _, err := s.userStore.FindByEmail(ctx, email); !errors.Is(err, store.ErrNotFound) {
		if err == nil {
			return nil, "", "", store.ErrConflict // Return a conflict error if user exists
		}
		return nil, "", "", err // Return other potential database errors
	}

	// In a real implementation, I would call a password hashing service here.
	// hashedPassword, err := s.passSvc.Hash(password)
	// For now, I'll use a placeholder.
	hashedPassword := "hashed_" + password

	now := time.Now()
	user := &domain.User{
		Email:        email,
		PasswordHash: hashedPassword,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.userStore.Create(ctx, user); err != nil {
		return nil, "", "", err
	}

	// Here I would generate encryption keys and call the token service.
	// await user.generateEncryptionKeys();
	// accessToken, refreshToken, err := s.tokenSvc.NewPair(ctx, *user, uuid)
	// For now, returning placeholder tokens.
	accessToken, refreshToken := "placeholder_access_token", "placeholder_refresh_token"

	// Here I would trigger the email verification flow if enabled.
	// if s.cfg.Email.VerificationEnabled { ... }

	return user, accessToken, refreshToken, nil
}

// Login handles the business logic for user authentication.
func (s *userService) Login(ctx context.Context, email, password, uuid string) (*domain.User, string, string, error) {
	user, err := s.userStore.FindByEmail(ctx, email)
	if err != nil {
		return nil, "", "", err // Returns store.ErrNotFound if user doesn't exist
	}

	// Here I would use the password service to compare the password.
	// if !s.passSvc.Compare(password, user.PasswordHash) {
	// 	return nil, "", "", store.ErrNotFound // Use same error to prevent email enumeration
	// }
	// Placeholder comparison:
	if user.PasswordHash != "hashed_"+password {
		return nil, "", "", store.ErrNotFound
	}

	// Generate new tokens upon successful login.
	// accessToken, refreshToken, err := s.tokenSvc.NewPair(ctx, *user, uuid)
	// For now, returning placeholder tokens.
	accessToken, refreshToken := "placeholder_access_token", "placeholder_refresh_token"

	return user, accessToken, refreshToken, nil
}

// ChangePassword handles the logic for updating a user's password.
func (s *userService) ChangePassword(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword, uuid string) (string, string, error) {
	user, err := s.userStore.FindByID(ctx, userID)
	if err != nil {
		return "", "", err
	}

	// Placeholder for password comparison
	if user.PasswordHash != "hashed_"+oldPassword {
		return "", "", errors.New("incorrect old password")
	}

	// Placeholder for new password hashing
	user.PasswordHash = "hashed_" + newPassword
	now := time.Now()
	user.PasswordLastModified = &now
	user.UpdatedAt = now
	// I would also clear the user.Tokens and user.TempTokens slices here.

	if err := s.userStore.Update(ctx, user); err != nil {
		return "", "", err
	}

	// Here I would re-encrypt the user's data with the new password hash derived key.
	// And generate new auth tokens.
	accessToken, refreshToken := "placeholder_access_token", "placeholder_refresh_token"

	return accessToken, refreshToken, nil
}
