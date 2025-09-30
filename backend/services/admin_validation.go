package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// Config interface for accessing configuration values needed for admin validation
type Config interface {
	GetDefaultAdminEmail() string
}

// ValidateEncryptionKeyAndAdminAccess checks for potential admin access issues due to encryption key changes
// Optimized version with combined queries and early exits
func ValidateEncryptionKeyAndAdminAccess(db Database, crypto CryptoService, adminEmail string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Println("🔍 Validating encryption key and admin access...")

	// Pre-generate admin email search hash to avoid redundant work
	currentEmailSearchHash, err := crypto.EncryptDeterministic([]byte(strings.ToLower(adminEmail)), "email_search")
	if err != nil {
		return fmt.Errorf("failed to generate current email search hash: %w", err)
	}

	// Combined query: Check user count and admin existence in a single query for efficiency
	var userCount int
	var adminExists bool
	err = db.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users) as user_count,
			EXISTS(SELECT 1 FROM users WHERE email_search_hash = $1) as admin_exists
	`, currentEmailSearchHash).Scan(&userCount, &adminExists)

	if err != nil {
		return fmt.Errorf("failed to check user status: %w", err)
	}

	if userCount == 0 {
		log.Println("✅ No users found - fresh installation, no key validation needed")
		return nil
	}

	if adminExists {
		log.Printf("✅ Admin user accessible with current encryption key (%d users total)", userCount)
		return nil
	}

	// Admin user not found - check if other users exist with encrypted hashes (indicating key mismatch)
	log.Printf("⚠️  ADMIN ACCESS ISSUE DETECTED!")
	log.Printf("   - Admin email: %s", adminEmail)
	log.Printf("   - Admin user not found with current encryption key")

	// Efficient check: just count users with email_search_hash (indicates encrypted users exist)
	var usersWithHashes int
	err = db.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE email_search_hash IS NOT NULL AND LENGTH(email_search_hash) > 0`).Scan(&usersWithHashes)
	if err != nil {
		log.Printf("Warning: Could not check for encrypted users, assuming key mismatch: %v", err)
		usersWithHashes = userCount // Assume worst case
	}

	if usersWithHashes > 0 {
		log.Printf("🚨 CRITICAL: Admin user unreachable due to encryption key mismatch!")
		log.Printf("   📊 Found %d users with encrypted hashes (out of %d total)", usersWithHashes, userCount)
		log.Printf("   This likely means the SERVER_ENCRYPTION_KEY has changed")
		log.Printf("")
		log.Printf("🔧 RECOVERY OPTIONS:")
		log.Printf("   1. Restore the original SERVER_ENCRYPTION_KEY if you have it")
		log.Printf("   2. Use the emergency admin recovery endpoint:")
		log.Printf("      POST /api/v1/auth/admin-recovery")
		log.Printf("      Body: {\"email\": \"%s\", \"password\": \"your_password\", \"recovery_token\": \"<token>\", \"confirm_deletion\": true}", adminEmail)
		log.Printf("")
		log.Printf("⚠️  WARNING: Recovery will delete the old admin user and create a new one!")

		return fmt.Errorf("admin user unreachable due to encryption key mismatch - see logs for recovery instructions")
	}

	log.Printf("ℹ️  No users with encrypted hashes found - may be legacy installation")
	return nil
}
