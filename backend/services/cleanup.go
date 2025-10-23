package services

import (
	"context"
	"log"
	"time"

	"leaflock/database"
)

// StartCleanupService starts a background cleanup service that runs every 24 hours
func StartCleanupService(db database.Database) {
	go func() {
		ctx := context.Background()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		// Run initial cleanup
		RunCleanupTasks(ctx, db)

		for range ticker.C {
			RunCleanupTasks(ctx, db)
		}
	}()
}

// RunCleanupTasks performs cleanup operations on the database
func RunCleanupTasks(ctx context.Context, db database.Database) {
	log.Println("🧹 Running scheduled cleanup tasks...")

	// Note: Session cleanup is now handled by Redis TTL

	// Reset failed login attempts for users who are no longer locked
	result, err := db.Exec(ctx, `
		UPDATE users
		SET failed_attempts = 0
		WHERE locked_until IS NOT NULL AND locked_until < NOW()
	`)
	if err != nil {
		log.Printf("⚠️ Failed to reset failed login attempts: %v", err)
	} else if result.RowsAffected() > 0 {
		log.Printf("✅ Reset failed login attempts for %d users", result.RowsAffected())
	}

	// Clean up old deleted notes (30+ days)
	_, err2 := db.Exec(ctx, "SELECT cleanup_old_deleted_notes()")
	if err2 != nil {
		log.Printf("⚠️ Failed to cleanup old deleted notes: %v", err2)
	} else {
		log.Println("✅ Cleaned up old deleted notes")
	}

	// Get count of deleted notes
	var deletedCount int
	_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM notes WHERE deleted_at < NOW() - INTERVAL '30 days' AND deleted_at IS NOT NULL").Scan(&deletedCount) // Best effort count

	if deletedCount > 0 {
		log.Printf("🗑️ Permanently deleted %d notes older than 30 days", deletedCount)
	}

	log.Println("🎯 Cleanup tasks completed successfully")
}
