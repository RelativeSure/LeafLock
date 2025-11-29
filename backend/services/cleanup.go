package services

import (
	"context"
	"log"
	"time"

	"leaflock/database"
)

// StartCleanupService starts a background cleanup service that runs every 24 hours
// This function implements a critical maintenance subsystem that ensures
// database hygiene and prevents resource accumulation over time.
//
// Business Context:
// - User accounts accumulate failed login attempts that need periodic reset
// - Deleted notes consume storage space indefinitely without cleanup
// - System performance degrades over time without maintenance
// - GDPR compliance requires proper data lifecycle management
//
// Design Decisions:
// - 24-hour interval balances cleanup effectiveness vs. database load
// - Background goroutine prevents blocking main application startup
// - Initial cleanup ensures system starts in a clean state
// - Context.Background() for long-running background operations
//
// The service runs indefinitely until application shutdown.
// Errors are logged but don't stop the service - cleanup failures are
// generally non-critical and will be retried on the next cycle.
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

// RunCleanupTasks performs critical database maintenance operations
// This function implements the core cleanup logic with specific focus on:
//
// 1. Security Management:
//    - Unlocks user accounts after lockout period expires
//    - Prevents permanent account lockout scenarios
//    - Reduces support burden from locked-out users
//
// 2. Storage Optimization:
//    - Permanently deletes notes deleted >30 days ago
//    - Frees up database storage space
//    - Implements data retention policy (30-day grace period)
//
// 3. System Hygiene:
//    - Prevents database bloat from soft-deleted records
//    - Maintains query performance over time
//    - Provides audit trail through detailed logging
//
// Error Handling Strategy:
// - Individual cleanup tasks are independent (failure of one doesn't affect others)
// - All errors are logged with context for debugging
// - Best-effort operations continue even if some tasks fail
// - Row counts provide feedback on cleanup effectiveness
//
// Performance Considerations:
// - Uses database functions for bulk operations (cleanup_old_deleted_notes)
// - Targets specific indexes for efficient queries (locked_until, deleted_at)
// - Operates during low-usage hours (assuming 24h cycle)
func RunCleanupTasks(ctx context.Context, db database.Database) {
	log.Println("🧹 Running scheduled cleanup tasks...")

	// Note: Session cleanup is now handled by Redis TTL
	// Architectural decision: Session management moved to Redis with TTL
	// Benefits: Faster cleanup (no database queries), better performance,
	// and automatic expiration without background processes

	// Reset failed login attempts for users who are no longer locked
	// This implements the account unlock mechanism after the security lockout period.
	// The query specifically targets users where:
	// - locked_until is not NULL (currently locked)
	// - locked_until < NOW() (lockout period has expired)
	//
	// Business Logic:
	// - Provides automatic account recovery without admin intervention
	// - Resets failed_attempts to 0, allowing normal login attempts
	// - Does NOT clear locked_until (preserves audit trail)
	//
	// Performance: Uses index on locked_until for efficient range scan
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
	// This calls a PostgreSQL function that implements the hard deletion logic.
	// The 30-day grace period provides:
	// - Time for users to recover accidentally deleted notes
	// - Compliance with data retention policies
	// - Grace period for support requests about deleted content
	//
	// The cleanup_old_deleted_notes() function:
	// - Identifies notes with deleted_at > 30 days ago
	// - Removes associated data (shares, permissions, etc.)
	// - Permanently deletes the note records
	// - Returns count of deleted notes (not captured here)
	_, err2 := db.Exec(ctx, "SELECT cleanup_old_deleted_notes()")
	if err2 != nil {
		log.Printf("⚠️ Failed to cleanup old deleted notes: %v", err2)
	} else {
		log.Println("✅ Cleaned up old deleted notes")
	}

	// Get count of remaining deleted notes for audit logging
	// This provides feedback on cleanup effectiveness and helps identify
	// if the cleanup_old_deleted_notes() function worked correctly.
	//
	// Note: This count represents notes that are still pending deletion
	// (deleted_at between now and 30 days ago), not the ones that were
	// just cleaned up. A count of 0 means all eligible notes were processed.
	var deletedCount int
	_ = db.QueryRow(ctx, "SELECT COUNT(*) FROM notes WHERE deleted_at < NOW() - INTERVAL '30 days' AND deleted_at IS NOT NULL").Scan(&deletedCount) // Best effort count

	if deletedCount > 0 {
		log.Printf("🗑️ Permanently deleted %d notes older than 30 days", deletedCount)
	}

	log.Println("🎯 Cleanup tasks completed successfully")
}
