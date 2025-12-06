// Package database provides the data access layer for LeafLock, implementing a secure
// and scalable PostgreSQL interface with automatic database setup and migrations.
//
// # Purpose and Responsibilities
//
// The database package serves as the foundational persistence layer, responsible for:
//   - Managing PostgreSQL connections with optimized connection pooling
//   - Executing automatic database creation and schema migrations on startup
//   - Providing a clean interface abstraction for dependency injection and testing
//   - Implementing secure SQL query patterns with proper parameterization
//   - Supporting transaction management for data consistency
//
// # Key Abstractions and Patterns
//
// Database Interface: The core Database interface enables dependency injection,
// making the entire application testable with mock implementations. This pattern
// allows handlers and services to remain decoupled from specific database
// implementations.
//
// Automatic Setup: The package implements automatic database creation and migration
// on application startup, eliminating manual database administration. This is
// crucial for cloud deployments where databases may not exist initially.
//
// Connection Pooling: Optimized connection pool configuration for managed
// PostgreSQL services (Railway, etc.) with health checks and connection lifecycle
// management.
//
// # Integration Points
//
// The database package is used by:
//   - handlers/: All HTTP request handlers for data persistence and retrieval
//   - services/: Background services for cleanup and maintenance operations
//   - auth/: Authentication and session management
//   - websocket/: Real-time collaboration state persistence
//
// # Security Considerations
//
//   - All SQL queries use parameterized statements to prevent SQL injection
//   - Database credentials are managed through environment variables
//   - Connection strings are parsed securely without exposing sensitive data
//   - Automatic identifier sanitization prevents unsafe table/column names
//   - Schema migrations are version-controlled and auditable
//
// # Architectural Decisions
//
// PostgreSQL-First Design: The package is optimized for PostgreSQL-specific
// features like UUID generation, JSON operations, and advanced indexing. This
// decision enables rich data types and performance optimizations while maintaining
// compatibility with managed PostgreSQL services.
//
// Zero-Downtime Migrations: Schema changes are designed to be backward-compatible
// during deployments, supporting continuous deployment practices without service
// interruption.
//
// Connection Pool Optimization: Pool settings are tuned for cloud environments
// where connection limits and timeouts are critical for reliability and performance.
package database
