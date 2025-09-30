// Package crypto provides encryption, decryption, and cryptographic utilities
// for the LeafLock application. It implements secure server-side encryption
// using XChaCha20-Poly1305 AEAD cipher with various encryption modes.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// CryptoService provides encryption and decryption operations using a server key.
// It supports multiple encryption modes including standard, deterministic,
// key derivation, and GDPR-compliant encryption with deletion keys.
type CryptoService struct {
	serverKey []byte
}

// NewCryptoService creates a new CryptoService instance with the provided server key.
// The key should be at least 32 bytes for secure XChaCha20-Poly1305 encryption.
func NewCryptoService(key []byte) *CryptoService {
	return &CryptoService{serverKey: key}
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with a random nonce.
// Returns the nonce prepended to the ciphertext.
func (c *CryptoService) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.serverKey[:32])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt.
// Expects the nonce to be prepended to the ciphertext.
func (c *CryptoService) Decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.serverKey[:32])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	return aead.Open(nil, nonce, ciphertext, nil)
}

// EncryptDeterministic encrypts plaintext using deterministic encryption.
// The same plaintext and context will always produce the same ciphertext.
// This is useful for searchable encryption but should be used carefully.
func (c *CryptoService) EncryptDeterministic(plaintext []byte, context string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte(context))
	h.Write(plaintext)
	deterministicKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(deterministicKey)
	if err != nil {
		return nil, err
	}

	h2 := sha256.New()
	h2.Write(deterministicKey)
	h2.Write(plaintext)
	nonce := h2.Sum(nil)[:aead.NonceSize()]

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// DecryptDeterministic decrypts deterministically encrypted ciphertext.
// Requires the expected plaintext to derive the correct decryption key.
func (c *CryptoService) DecryptDeterministic(ciphertext []byte, context string, expectedPlaintext []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte(context))
	h.Write(expectedPlaintext)
	deterministicKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(deterministicKey)
	if err != nil {
		return nil, err
	}

	h2 := sha256.New()
	h2.Write(deterministicKey)
	h2.Write(expectedPlaintext)
	nonce := h2.Sum(nil)[:aead.NonceSize()]

	return aead.Open(nil, nonce, ciphertext, nil)
}

// EncryptWithKeyDerivation encrypts plaintext using a key derived from the server key
// and a key type identifier. This allows different data types to use different derived keys.
func (c *CryptoService) EncryptWithKeyDerivation(plaintext []byte, keyType string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte("field:" + keyType))
	fieldKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(fieldKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// DecryptWithKeyDerivation decrypts ciphertext encrypted with EncryptWithKeyDerivation.
// Must use the same keyType that was used during encryption.
func (c *CryptoService) DecryptWithKeyDerivation(ciphertext []byte, keyType string) ([]byte, error) {
	h := sha256.New()
	h.Write(c.serverKey[:32])
	h.Write([]byte("field:" + keyType))
	fieldKey := h.Sum(nil)[:32]

	aead, err := chacha20poly1305.NewX(fieldKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// EncryptWithGDPRKey encrypts plaintext using a GDPR deletion key.
// This enables secure data deletion by destroying the deletion key.
func (c *CryptoService) EncryptWithGDPRKey(plaintext []byte, deletionKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deletionKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// DecryptWithGDPRKey decrypts ciphertext encrypted with EncryptWithGDPRKey.
// Requires the same deletion key that was used during encryption.
func (c *CryptoService) DecryptWithGDPRKey(ciphertext []byte, deletionKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(deletionKey)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// HashEmail creates a SHA-256 hash of an email address (case-insensitive).
// Useful for email lookup while maintaining privacy.
func (c *CryptoService) HashEmail(email string) []byte {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(email)))
	return h.Sum(nil)
}