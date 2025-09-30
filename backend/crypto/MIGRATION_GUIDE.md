# Migration Guide: Using the Crypto Package

This guide explains how to update `main.go` to use the new `crypto` package.

## Step 1: Update Imports

In `main.go`, add the crypto package import:

```go
import (
    // ... existing imports ...
    "leaflock/crypto"  // Add this line
)
```

## Step 2: Remove Crypto-Related Code from main.go

Remove the following from `main.go`:

### Remove CryptoService struct definition (around line 749):
```go
// DELETE THIS:
type CryptoService struct {
	serverKey []byte
}
```

### Remove NewCryptoService function (around line 1017):
```go
// DELETE THIS:
func NewCryptoService(key []byte) *CryptoService {
	return &CryptoService{serverKey: key}
}
```

### Remove all Encrypt/Decrypt methods (lines ~1364-1501):
```go
// DELETE ALL THESE METHODS:
func (c *CryptoService) Encrypt(plaintext []byte) ([]byte, error) { ... }
func (c *CryptoService) Decrypt(ciphertext []byte) ([]byte, error) { ... }
func (c *CryptoService) EncryptDeterministic(...) { ... }
func (c *CryptoService) DecryptDeterministic(...) { ... }
func (c *CryptoService) EncryptWithKeyDerivation(...) { ... }
func (c *CryptoService) DecryptWithKeyDerivation(...) { ... }
func (c *CryptoService) EncryptWithGDPRKey(...) { ... }
func (c *CryptoService) DecryptWithGDPRKey(...) { ... }
func (c *CryptoService) HashEmail(email string) []byte { ... }
```

### Remove password functions (lines ~1504-1523):
```go
// DELETE THESE:
func HashPassword(password string, salt []byte) string { ... }
func VerifyPassword(password, encodedHash string) bool { ... }
```

## Step 3: Update Type References

Update the `ReadyState` struct to use the crypto package type:

```go
type ReadyState struct {
	db             *pgxpool.Pool
	crypto         *crypto.CryptoService  // Change from *CryptoService
	config         *Config
	// ... rest of fields
}
```

## Step 4: Update Function Calls

Replace all crypto function calls throughout main.go:

### CryptoService creation:
```go
// OLD:
cryptoService := NewCryptoService(serverKey)

// NEW:
cryptoService := crypto.NewCryptoService(serverKey)
```

### Password hashing:
```go
// OLD:
hash := HashPassword(password, salt)

// NEW:
hash := crypto.HashPassword(password, salt)
```

### Password verification:
```go
// OLD:
if !VerifyPassword(password, storedHash) {

// NEW:
if !crypto.VerifyPassword(password, storedHash) {
```

### CryptoService method calls remain the same:
```go
// These calls don't change because they're methods on the service:
ciphertext, err := cryptoService.Encrypt(plaintext)
decrypted, err := cryptoService.Decrypt(ciphertext)
emailHash := cryptoService.HashEmail(email)
// ... etc
```

## Step 5: Verify the Changes

Run the following commands to verify everything works:

```bash
# Build the application
cd backend
go build -o app .

# Run tests
go test ./...

# If you have integration tests, run them
go test -v ./... -tags=integration
```

## Example: Before and After

### Before (main.go):
```go
package main

import (
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/argon2"
    // ... other imports
)

type CryptoService struct {
	serverKey []byte
}

func NewCryptoService(key []byte) *CryptoService {
	return &CryptoService{serverKey: key}
}

func (c *CryptoService) Encrypt(plaintext []byte) ([]byte, error) {
    // implementation...
}

func HashPassword(password string, salt []byte) string {
    // implementation...
}

func main() {
    cryptoService := NewCryptoService(serverKey)
    hash := HashPassword(password, salt)
    // ...
}
```

### After (main.go):
```go
package main

import (
    "leaflock/crypto"
    // ... other imports (remove crypto/chacha20poly1305 and crypto/argon2 if not used elsewhere)
)

// CryptoService struct removed
// NewCryptoService function removed
// All crypto methods removed
// HashPassword and VerifyPassword functions removed

func main() {
    cryptoService := crypto.NewCryptoService(serverKey)
    hash := crypto.HashPassword(password, salt)
    // ...
}
```

## Benefits of This Refactoring

1. **Better Code Organization**: Crypto logic is separated from business logic
2. **Easier Testing**: Crypto functions can be tested independently
3. **Improved Maintainability**: Crypto code is in one place
4. **Reusability**: The crypto package can be used by other packages
5. **Clear Dependencies**: Crypto imports are isolated to the crypto package
6. **Better Documentation**: Crypto functionality is self-documenting

## Rollback Plan

If you need to rollback:

1. Remove the import of `leaflock/crypto`
2. Copy the crypto functions back from the crypto package to main.go
3. Revert the function calls (remove `crypto.` prefix)

## Testing After Migration

Create a test to verify the migration works:

```go
func TestCryptoMigration(t *testing.T) {
    // Test that crypto service works
    key := make([]byte, 32)
    rand.Read(key)
    cs := crypto.NewCryptoService(key)

    plaintext := []byte("test data")
    ciphertext, err := cs.Encrypt(plaintext)
    if err != nil {
        t.Fatalf("Encryption failed: %v", err)
    }

    decrypted, err := cs.Decrypt(ciphertext)
    if err != nil {
        t.Fatalf("Decryption failed: %v", err)
    }

    if !bytes.Equal(plaintext, decrypted) {
        t.Error("Decryption mismatch")
    }

    // Test password hashing
    salt := make([]byte, 16)
    rand.Read(salt)
    hash := crypto.HashPassword("password", salt)

    if !crypto.VerifyPassword("password", hash) {
        t.Error("Password verification failed")
    }
}
```

## Need Help?

If you encounter issues:
1. Check that all imports are correct
2. Verify that the crypto package compiles: `go build ./crypto`
3. Run crypto package tests: `go test ./crypto -v`
4. Check for any remaining references to the old functions