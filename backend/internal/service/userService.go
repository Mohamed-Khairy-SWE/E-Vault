package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"E-Vault/internal/config"
	"E-Vault/internal/domain"
	"E-Vault/internal/platform/crypto"
	"E-Vault/internal/platform/email"
	"E-Vault/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// UserService defines the interface for user-related business logic.
type UserService interface {
	Create(ctx context.Context, email, password string) (*domain.User, string, string, error)
	Login(ctx context.Context, email, password string) (*domain.User, string, string, error)
	ChangePassword(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword string) (string, string, error)
	SendVerificationEmail(ctx context.Context, userID bson.ObjectID) error
	// Additional methods like Logout, VerifyEmail, etc., would be defined here.
}

// userService is the concrete implementation of the UserService interface.
type userService struct {
	userStore store.UserStore
	cfg       config.Config
	tokenSvc  crypto.TokenGenerator
	passSvc   crypto.PasswordManager
	emailSvc  email.EmailService
}

// NewUserService creates a new instance of the user service.
func NewUserService(
	userStore store.UserStore,
	cfg config.Config,
	ts crypto.TokenGenerator,
	ps crypto.PasswordManager,
	es email.EmailService,
) UserService {
	return &userService{
		userStore: userStore,
		cfg:       cfg,
		tokenSvc:  ts,
		passSvc:   ps,
		emailSvc:  es,
	}
}

// Create handles the business logic for registering a new user
func (s *userService) Create(ctx context.Context, email, password string) (*domain.User, string, string, error) {
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

	hashedPassword, err := s.passSvc.Hash(password)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to hash password: %w", err)
	}

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

	accessToken, refreshToken, err := s.tokenSvc.NewPair(user)

	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create token pair: %w", err)
	}

	// If email verification is enabled, send the verification email
	if s.cfg.Email.VerificationEnabled {
		go func() {
			//Sending email can be slow, so we do it in a background goroutine
			// to not block the user's registration response
			// We'll generate a dedicated, short-lived token for this
			// This logic will be fully implemented when we add token parsing
			err := s.emailSvc.SendVerificationEmail(user, "placeholder-email-token")
			if err != nil {
				fmt.Printf("Failed to send verification email to %s: %v\n", user.Email, err)
			}
		}()
	}

	return user, accessToken, refreshToken, nil
}

// SendVerificationEmail handles the logic for resending a verification email.
func (s *userService) SendVerificationEmail(ctx context.Context, userID bson.ObjectID) error {
	if !s.cfg.Email.VerificationEnabled {
		return errors.New("email verification is not enabled")
	}

	user, err := s.userStore.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.EmailVerified != nil && *user.EmailVerified {
		return errors.New("email is already verified")
	}

	// This logic will be expanded when we can generate and store the email-specific token.
	return s.emailSvc.SendVerificationEmail(user, "placeholder-email-token")
}

// Login handles the business logic for user authentication.
func (s *userService) Login(ctx context.Context, email, password string) (*domain.User, string, string, error) {
	user, err := s.userStore.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", "", errors.New("invalid credentials")
		}
		return nil, "", "", err
	}

	if err := s.passSvc.Compare(user.PasswordHash, password); err != nil {
		return nil, "", "", errors.New("invalid credentials")
	}

	accessToken, refreshToken, err := s.tokenSvc.NewPair(user)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create token pair: %w", err)
	}

	return user, accessToken, refreshToken, nil
}

// ChangePassword handles the logic for updating a user's password.
func (s *userService) ChangePassword(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword string) (string, string, error) {
	user, err := s.userStore.FindByID(ctx, userID)
	if err != nil {
		return "", "", err
	}

	// Verify the old password.
	if err := s.passSvc.Compare(user.PasswordHash, oldPassword); err != nil {
		return "", "", errors.New("incorrect old password")
	}

	// Hash the new password.
	newHashedPassword, err := s.passSvc.Hash(newPassword)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash new password: %w", err)
	}

	// Placeholder for new password hashing
	user.PasswordHash = newHashedPassword
	now := time.Now()
	user.PasswordLastModified = &now
	user.UpdatedAt = now
	user.Tokens = []domain.AuthToken{} // Invalidate all old refresh tokens.
	user.TempTokens = []domain.AuthToken{}

	if err := s.userStore.Update(ctx, user); err != nil {
		return "", "", err
	}

	// NOTE: Logic to re-encrypt user data with the new key would be added here.

	// Issue a new set of tokens.
	accessToken, refreshToken, err := s.tokenSvc.NewPair(user)
	if err != nil {
		return "", "", fmt.Errorf("failed to create token pair after password change: %w", err)
	}

	return accessToken, refreshToken, nil
}
