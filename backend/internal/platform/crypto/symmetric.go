package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// GenerateIV creates a new random Initialization Vector (IV) for AES encryption.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize) // 16 bytes for AES
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// DeriveKeyFromPassword creates a 32-byte key from a given string using SHA-256,
// mirroring the logic from the original Node.js crypto.createHash('sha256').
func DeriveKeyFromPassword(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// EncryptAES uses AES-256-CBC to encrypt data. It pads the data to be a multiple
// of the block size using PKCS#7 padding.
func EncryptAES(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Apply PKCS#7 padding to the data.
	paddedData, err := pkcs7Pad(data, block.BlockSize())
	if err != nil {
		return nil, fmt.Errorf("failed to pad data: %w", err)
	}

	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

// DecryptAES uses AES-256-CBC to decrypt data and removes PKCS#7 padding.
func DecryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData := make([]byte, len(ciphertext))
	mode.CryptBlocks(decryptedData, ciphertext)

	// Remove PKCS#7 padding.
	unpaddedData, err := pkcs7Unpad(decryptedData, block.BlockSize())
	if err != nil {
		return nil, fmt.Errorf("failed to unpad data: %w", err)
	}

	return unpaddedData, nil
}

// --- PKCS#7 Padding Helpers ---

func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	if len(data) == 0 {
		return nil, errors.New("cannot unpad empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("data is not block-aligned")
	}
	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := 0; i < padding; i++ {
		if int(data[len(data)-1-i]) != padding {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
