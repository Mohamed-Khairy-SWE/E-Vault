package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// KeyManager handles the generation and retrieval of the user-specific master encryption key.
// This key is used to encrypt all of the user's files.
type KeyManager struct {
	masterAppKey string
}

// NewKeyManager creates a new KeyManager. It requires the application's global master key.
func NewKeyManager(masterAppKey string) *KeyManager {
	return &KeyManager{masterAppKey: masterAppKey}
}

// GenerateUserKeys creates a new random 32-byte key for a user and encrypts it
// in a two-layer process, returning the hex-encoded private key and public IV.
// This replicates the `generateEncryptionKeys` logic.
func (km *KeyManager) GenerateUserKeys(userPassword string) (privateKeyHex, publicIVHex string, err error) {
	// 1. Generate a new random key for the user's files.
	randomFileKey := make([]byte, 32)
	if _, err := rand.Read(randomFileKey); err != nil {
		return "", "", fmt.Errorf("failed to generate random file key: %w", err)
	}

	// 2. Generate a new IV for this encryption operation.
	iv, err := GenerateIV()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// 3. Encrypt the random file key with a key derived from the user's password.
	userCipherKey := DeriveKeyFromPassword(userPassword)
	encryptedWithUserKey, err := EncryptAES(randomFileKey, userCipherKey, iv)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt with user key: %w", err)
	}

	// 4. Encrypt the result again, this time with a key derived from the app's master key.
	masterCipherKey := DeriveKeyFromPassword(km.masterAppKey)
	finalEncryptedKey, err := EncryptAES(encryptedWithUserKey, masterCipherKey, iv)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt with master key: %w", err)
	}

	return hex.EncodeToString(finalEncryptedKey), hex.EncodeToString(iv), nil
}

// GetUserFileKey decrypts the stored user keys to retrieve the raw file encryption key.
// This replicates the `getEncryptionKey` logic.
func (km *KeyManager) GetUserFileKey(userPassword, privateKeyHex, publicIVHex string) ([]byte, error) {
	// 1. Decode the hex-encoded inputs.
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	iv, err := hex.DecodeString(publicIVHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public iv hex: %w", err)
	}

	// 2. Derive the same keys used during encryption.
	userCipherKey := DeriveKeyFromPassword(userPassword)
	masterCipherKey := DeriveKeyFromPassword(km.masterAppKey)

	// 3. Decrypt the outer layer using the app's master key.
	decryptedWithMasterKey, err := DecryptAES(privateKey, masterCipherKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with master key: %w", err)
	}

	// 4. Decrypt the inner layer using the user's password-derived key.
	finalKey, err := DecryptAES(decryptedWithMasterKey, userCipherKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with user key: %w", err)
	}

	return finalKey, nil
}
