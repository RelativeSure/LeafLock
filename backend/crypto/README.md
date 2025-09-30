# Crypto Package

Cryptographic utilities for the LeafLock application, providing secure encryption, decryption, and password hashing functionality.

## Overview

This package implements:
- **XChaCha20-Poly1305 AEAD encryption** for server-side data protection
- **Argon2id password hashing** with secure parameters
- **Multiple encryption modes** for different use cases
- **GDPR-compliant encryption** with deletion keys

## Components

### CryptoService

The main service for encryption and decryption operations.

```go
// Create a new CryptoService
key := make([]byte, 32)
rand.Read(key)
cs := crypto.NewCryptoService(key)
```

### Encryption Methods

#### Standard Encryption
Random nonce for each encryption. Same plaintext produces different ciphertext.

```go
ciphertext, err := cs.Encrypt(plaintext)
decrypted, err := cs.Decrypt(ciphertext)
```

#### Deterministic Encryption
Same plaintext and context produce identical ciphertext. Useful for searchable encryption.

```go
ciphertext, err := cs.EncryptDeterministic(plaintext, "email")
decrypted, err := cs.DecryptDeterministic(ciphertext, "email", plaintext)
```

#### Key Derivation Encryption
Derives unique keys for different data types.

```go
ciphertext, err := cs.EncryptWithKeyDerivation(plaintext, "user_email")
decrypted, err := cs.DecryptWithKeyDerivation(ciphertext, "user_email")
```

#### GDPR Encryption
Encryption with user-specific deletion keys for GDPR compliance.

```go
deletionKey := make([]byte, 32)
rand.Read(deletionKey)
ciphertext, err := cs.EncryptWithGDPRKey(plaintext, deletionKey)
decrypted, err := cs.DecryptWithGDPRKey(ciphertext, deletionKey)
```

### Password Functions

#### Hash Password
Secure password hashing with Argon2id.

```go
salt := make([]byte, 16)
rand.Read(salt)
hash := crypto.HashPassword("password123", salt)
```

**Parameters:**
- Memory: 64MB
- Iterations: 3
- Parallelism: 4 threads
- Hash length: 32 bytes

#### Verify Password
Constant-time password verification.

```go
isValid := crypto.VerifyPassword("password123", hash)
```

### Email Hashing
SHA-256 hash of email addresses (case-insensitive).

```go
emailHash := cs.HashEmail("user@example.com")
```

## Security Features

- **XChaCha20-Poly1305**: Authenticated encryption with extended nonce size
- **Random nonces**: Prevents ciphertext reuse
- **Argon2id**: Memory-hard password hashing resistant to GPU attacks
- **Constant-time comparison**: Prevents timing attacks
- **Key derivation**: Separate keys for different data types
- **GDPR compliance**: Cryptographic data deletion via key destruction

## Test Coverage

The package has **86.6% test coverage** with comprehensive tests for:
- Encryption/decryption round trips
- Deterministic encryption behavior
- Key derivation isolation
- GDPR key functionality
- Password hashing and verification
- Edge cases (empty data, large data, invalid inputs)
- Timing attack resistance

Run tests:
```bash
go test -v ./crypto
go test -cover ./crypto
go test -bench=. ./crypto
```

## Performance

Benchmark results on Intel Core i5-11600KF @ 3.90GHz:

| Operation | Time/op | Memory/op | Allocs/op |
|-----------|---------|-----------|-----------|
| Encrypt | 768 ns | 216 B | 4 |
| Decrypt | 322 ns | 80 B | 2 |
| Deterministic Encrypt | 544 ns | 128 B | 4 |
| Hash Email | 120 ns | 32 B | 1 |
| Hash Password | ~61 ms | ~67 MB | 101 |
| Verify Password | ~64 ms | ~67 MB | 92 |

Note: Password operations are intentionally slow to resist brute-force attacks.

## Usage Example

```go
package main

import (
    "crypto/rand"
    "fmt"
    "leaflock/crypto"
)

func main() {
    // Initialize crypto service
    serverKey := make([]byte, 32)
    rand.Read(serverKey)
    cs := crypto.NewCryptoService(serverKey)

    // Encrypt user data
    plaintext := []byte("Sensitive user data")
    ciphertext, err := cs.Encrypt(plaintext)
    if err != nil {
        panic(err)
    }

    // Decrypt user data
    decrypted, err := cs.Decrypt(ciphertext)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(decrypted))

    // Hash password
    salt := make([]byte, 16)
    rand.Read(salt)
    hash := crypto.HashPassword("SecurePassword123!", salt)

    // Verify password
    if crypto.VerifyPassword("SecurePassword123!", hash) {
        fmt.Println("Password verified!")
    }
}
```

## Dependencies

- `golang.org/x/crypto/chacha20poly1305` - XChaCha20-Poly1305 AEAD
- `golang.org/x/crypto/argon2` - Argon2id password hashing
- `crypto/rand` - Cryptographically secure random number generation
- `crypto/sha256` - SHA-256 hashing
- `crypto/subtle` - Constant-time comparison

## License

Part of the LeafLock application.