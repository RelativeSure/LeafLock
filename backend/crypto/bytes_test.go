package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptDecryptBytes tests encrypting and decrypting raw bytes
func TestEncryptDecryptBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	
	svc := NewCryptoService(key)
	
	tests := []struct {
		name string
		data []byte
	}{
		{"Short data", []byte("Hello, World!")},
		{"Long data", []byte("This is a much longer piece of data that needs to be encrypted and decrypted properly")},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"Empty data", []byte("")},
		{"Single byte", []byte{0x42}},
		{"Unicode data", []byte("Hello 世界 🔐")},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			encrypted, err := svc.EncryptBytes(tt.data)
			require.NoError(t, err)
			assert.NotEmpty(t, encrypted)
			assert.NotEqual(t, tt.data, encrypted)
			
			// Decrypt
			decrypted, err := svc.DecryptBytes(encrypted)
			require.NoError(t, err)
			assert.Equal(t, tt.data, decrypted)
		})
	}
}

// TestEncryptBytes_Uniqueness tests that same plaintext produces different ciphertext
func TestEncryptBytes_Uniqueness(t *testing.T) {
	key := make([]byte, 32)
	svc := NewCryptoService(key)
	
	data := []byte("Same data")
	
	encrypted1, err1 := svc.EncryptBytes(data)
	require.NoError(t, err1)
	
	encrypted2, err2 := svc.EncryptBytes(data)
	require.NoError(t, err2)
	
	// Should produce different ciphertext due to random nonce
	assert.NotEqual(t, encrypted1, encrypted2)
	
	// But both should decrypt to same plaintext
	decrypted1, _ := svc.DecryptBytes(encrypted1)
	decrypted2, _ := svc.DecryptBytes(encrypted2)
	assert.Equal(t, data, decrypted1)
	assert.Equal(t, data, decrypted2)
}

// TestDecryptBytes_InvalidData tests decryption with invalid data
func TestDecryptBytes_InvalidData(t *testing.T) {
	key := make([]byte, 32)
	svc := NewCryptoService(key)
	
	tests := []struct {
		name string
		data []byte
	}{
		{"Empty data", []byte{}},
		{"Too short", []byte{0x00, 0x01}},
		{"Invalid ciphertext", []byte("this is not encrypted")},
		{"Corrupted data", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.DecryptBytes(tt.data)
			assert.Error(t, err)
		})
	}
}

// TestEncryptBytes_LargeData tests encryption of large data
func TestEncryptBytes_LargeData(t *testing.T) {
	key := make([]byte, 32)
	svc := NewCryptoService(key)
	
	// Create 1MB of data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	
	encrypted, err := svc.EncryptBytes(largeData)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	
	decrypted, err := svc.DecryptBytes(encrypted)
	require.NoError(t, err)
	assert.Equal(t, largeData, decrypted)
}

// TestDecryptBytes_WrongKey tests decryption with wrong key
func TestDecryptBytes_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}
	
	svc1 := NewCryptoService(key1)
	svc2 := NewCryptoService(key2)
	
	data := []byte("Secret message")
	
	encrypted, err := svc1.EncryptBytes(data)
	require.NoError(t, err)
	
	// Try to decrypt with wrong key
	_, err = svc2.DecryptBytes(encrypted)
	assert.Error(t, err)
}
