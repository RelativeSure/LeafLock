package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// HashPassword securely hashes a password using Argon2id with the provided salt.
// Returns an encoded string containing the algorithm parameters, salt, and hash.
//
// Parameters:
//   - Memory: 64MB (64*1024 KB)
//   - Iterations: 3
//   - Parallelism: 4 threads
//   - Hash length: 32 bytes
//
// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func HashPassword(password string, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 64*1024, 3, 4, b64Salt, b64Hash)
}

// VerifyPassword verifies a password against an Argon2id encoded hash.
// Uses constant-time comparison to prevent timing attacks.
//
// Returns true if the password matches the hash, false otherwise.
func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false
	}

	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	hash, _ := base64.RawStdEncoding.DecodeString(parts[5])

	comparisonHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1
}