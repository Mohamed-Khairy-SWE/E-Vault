package crypto

import "golang.org/x/crypto/bcrypt"

// PasswordManager provides an interface for hashing and comparing passwords
type PasswordManager interface {
	Hash(password string) (string, error)
	Compare(hashedPassword, password string) error
}

// BcryptManager is a concrete implementation of PasswordManager using bcrypt
type BcryptManager struct {
	cost int
}

// NewBcryptManager creates a new BcryptManager
// The cost parameter determines the complexity of the hash. A higher cost is more
// secure but slower. bcrypt.DefaultCost (10) is a good starting point
func NewBcryptManager(cost int) *BcryptManager {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	return &BcryptManager{cost: cost}
}

// Hash generates a bcrypt hash of the password
func (m *BcryptManager) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), m.cost)
	return string(bytes), err
}

// Compare securely compares a hashed password with a plaintext password
// It returns nil on success and an error on failure, which prevents timing attacks
func (m *BcryptManager) Compare(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
