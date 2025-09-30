package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestNewCryptoService tests the creation of a new CryptoService
func TestNewCryptoService(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	if cs == nil {
		t.Fatal("NewCryptoService returned nil")
	}
	if !bytes.Equal(cs.serverKey, key) {
		t.Error("CryptoService key does not match provided key")
	}
}

// TestEncryptDecrypt tests basic encryption and decryption round trip
func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("Hello, LeafLock!")

	// Encrypt
	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	// Decrypt
	decrypted, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestEncryptRandomness tests that encryption produces different ciphertexts for the same plaintext
func TestEncryptRandomness(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("Same plaintext")

	ciphertext1, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	ciphertext2, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// Two encryptions of the same plaintext should produce different ciphertexts (due to random nonce)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Two encryptions of the same plaintext should produce different ciphertexts")
	}

	// Both should decrypt to the same plaintext
	decrypted1, _ := cs.Decrypt(ciphertext1)
	decrypted2, _ := cs.Decrypt(ciphertext2)
	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("Both ciphertexts should decrypt to the same plaintext")
	}
}

// TestDecryptInvalidCiphertext tests decryption with invalid data
func TestDecryptInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	// Test with too-short ciphertext
	_, err = cs.Decrypt([]byte("short"))
	if err == nil {
		t.Error("Decrypt should fail with too-short ciphertext")
	}

	// Test with corrupted ciphertext
	plaintext := []byte("Valid plaintext")
	ciphertext, _ := cs.Encrypt(plaintext)
	ciphertext[len(ciphertext)-1] ^= 0xFF // Corrupt last byte
	_, err = cs.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail with corrupted ciphertext")
	}
}

// TestEncryptDecryptDeterministic tests deterministic encryption
func TestEncryptDecryptDeterministic(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("test@example.com")
	context := "email"

	// Encrypt twice with same context
	ciphertext1, err := cs.EncryptDeterministic(plaintext, context)
	if err != nil {
		t.Fatalf("First deterministic encrypt failed: %v", err)
	}

	ciphertext2, err := cs.EncryptDeterministic(plaintext, context)
	if err != nil {
		t.Fatalf("Second deterministic encrypt failed: %v", err)
	}

	// Deterministic encryption should produce identical ciphertexts
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Deterministic encryption should produce identical ciphertexts for the same input")
	}

	// Decrypt
	decrypted, err := cs.DecryptDeterministic(ciphertext1, context, plaintext)
	if err != nil {
		t.Fatalf("Deterministic decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestDeterministicContextSeparation tests that different contexts produce different ciphertexts
func TestDeterministicContextSeparation(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("same plaintext")

	ciphertext1, _ := cs.EncryptDeterministic(plaintext, "context1")
	ciphertext2, _ := cs.EncryptDeterministic(plaintext, "context2")

	// Different contexts should produce different ciphertexts
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Different contexts should produce different ciphertexts")
	}
}

// TestEncryptDecryptWithKeyDerivation tests key derivation encryption
func TestEncryptDecryptWithKeyDerivation(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("Sensitive field data")
	keyType := "user_email"

	// Encrypt
	ciphertext, err := cs.EncryptWithKeyDerivation(plaintext, keyType)
	if err != nil {
		t.Fatalf("EncryptWithKeyDerivation failed: %v", err)
	}

	// Decrypt
	decrypted, err := cs.DecryptWithKeyDerivation(ciphertext, keyType)
	if err != nil {
		t.Fatalf("DecryptWithKeyDerivation failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestKeyDerivationTypeSeparation tests that different key types cannot decrypt each other's data
func TestKeyDerivationTypeSeparation(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("test data")

	ciphertext, _ := cs.EncryptWithKeyDerivation(plaintext, "type1")

	// Try to decrypt with wrong key type
	_, err = cs.DecryptWithKeyDerivation(ciphertext, "type2")
	if err == nil {
		t.Error("Decryption should fail when using wrong key type")
	}
}

// TestEncryptDecryptWithGDPRKey tests GDPR-compliant encryption with deletion keys
func TestEncryptDecryptWithGDPRKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	deletionKey := make([]byte, 32)
	_, err = rand.Read(deletionKey)
	if err != nil {
		t.Fatalf("Failed to generate deletion key: %v", err)
	}

	plaintext := []byte("GDPR protected data")

	// Encrypt
	ciphertext, err := cs.EncryptWithGDPRKey(plaintext, deletionKey)
	if err != nil {
		t.Fatalf("EncryptWithGDPRKey failed: %v", err)
	}

	// Decrypt
	decrypted, err := cs.DecryptWithGDPRKey(ciphertext, deletionKey)
	if err != nil {
		t.Fatalf("DecryptWithGDPRKey failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestGDPRKeyDeletion tests that data becomes unrecoverable without the deletion key
func TestGDPRKeyDeletion(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	deletionKey := make([]byte, 32)
	_, err = rand.Read(deletionKey)
	if err != nil {
		t.Fatalf("Failed to generate deletion key: %v", err)
	}

	plaintext := []byte("Data to be forgotten")
	ciphertext, _ := cs.EncryptWithGDPRKey(plaintext, deletionKey)

	// Simulate key deletion by using wrong key
	wrongKey := make([]byte, 32)
	_, err = rand.Read(wrongKey)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	_, err = cs.DecryptWithGDPRKey(ciphertext, wrongKey)
	if err == nil {
		t.Error("Decryption should fail with wrong deletion key")
	}
}

// TestHashEmail tests email hashing functionality
func TestHashEmail(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	email := "user@example.com"
	hash1 := cs.HashEmail(email)
	hash2 := cs.HashEmail(email)

	// Same email should produce same hash
	if !bytes.Equal(hash1, hash2) {
		t.Error("Same email should produce same hash")
	}

	// Hash should be 32 bytes (SHA-256)
	if len(hash1) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(hash1))
	}

	// Different emails should produce different hashes
	hash3 := cs.HashEmail("different@example.com")
	if bytes.Equal(hash1, hash3) {
		t.Error("Different emails should produce different hashes")
	}
}

// TestHashEmailCaseInsensitive tests that email hashing is case-insensitive
func TestHashEmailCaseInsensitive(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	hash1 := cs.HashEmail("User@Example.Com")
	hash2 := cs.HashEmail("user@example.com")
	hash3 := cs.HashEmail("USER@EXAMPLE.COM")

	// All variations should produce the same hash
	if !bytes.Equal(hash1, hash2) || !bytes.Equal(hash2, hash3) {
		t.Error("Email hashing should be case-insensitive")
	}
}

// TestEmptyPlaintext tests encryption and decryption of empty data
func TestEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)
	plaintext := []byte("")

	// Test standard encryption
	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt empty plaintext failed: %v", err)
	}

	decrypted, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty plaintext failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Empty plaintext encryption/decryption failed")
	}
}

// TestLargePlaintext tests encryption and decryption of large data
func TestLargePlaintext(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	cs := NewCryptoService(key)

	// Create 1MB of random data
	plaintext := make([]byte, 1024*1024)
	_, err = rand.Read(plaintext)
	if err != nil {
		t.Fatalf("Failed to generate large plaintext: %v", err)
	}

	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt large plaintext failed: %v", err)
	}

	decrypted, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt large plaintext failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Large plaintext encryption/decryption failed")
	}
}

// BenchmarkEncrypt benchmarks the encryption performance
func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cs := NewCryptoService(key)
	plaintext := []byte("Benchmark plaintext data for encryption testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cs.Encrypt(plaintext)
	}
}

// BenchmarkDecrypt benchmarks the decryption performance
func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cs := NewCryptoService(key)
	plaintext := []byte("Benchmark plaintext data for decryption testing")
	ciphertext, _ := cs.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cs.Decrypt(ciphertext)
	}
}

// BenchmarkEncryptDeterministic benchmarks deterministic encryption
func BenchmarkEncryptDeterministic(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cs := NewCryptoService(key)
	plaintext := []byte("test@example.com")
	context := "email"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cs.EncryptDeterministic(plaintext, context)
	}
}

// BenchmarkHashEmail benchmarks email hashing
func BenchmarkHashEmail(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	cs := NewCryptoService(key)
	email := "user@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cs.HashEmail(email)
	}
}