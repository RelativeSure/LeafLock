// Package services implements background and utility services that support the
// core functionality of LeafLock, providing cross-cutting concerns like email
// delivery, data cleanup, and template management.
//
// # Purpose and Responsibilities
//
// The services package encapsulates operational concerns that don't fit neatly
// into request-response patterns, including:
//   - Email notification delivery with template support
//   - Automated cleanup of expired data and system maintenance
//   - Default template seeding for new user onboarding
//   - Share link management and validation
//   - Allowlist management for access control
//
// # Key Abstractions and Patterns
//
// Service Pattern: Each service is implemented as a struct with dependency
// injection, following the same pattern as handlers. This enables consistent
// configuration management and testability.
//
// Background Processing: Long-running operations like cleanup run in dedicated
// goroutines with proper context management and error handling, ensuring they
// don't impact request processing.
//
// Template System: Email and note templates use Go's html/template package
// with data-driven content generation, supporting both HTML and plain text formats.
//
// # Integration Points
//
// The services package integrates with:
//   - config/: Centralized configuration management for SMTP settings
//   - database/: Data persistence for templates, allowlists, and share links
//   - handlers/: Triggered by user actions like registration or sharing
//   - main/: Service initialization and lifecycle management
//
// # Security Considerations
//
//   - Email templates are validated to prevent injection attacks
//   - SMTP connections support TLS with configurable security levels
//   - Share links use cryptographically secure random generation
//   - Cleanup operations use parameterized queries to prevent SQL injection
//   - Allowlist validation prevents unauthorized access attempts
//
// # Architectural Decisions
//
// Separation of Concerns: Services are kept separate from handlers to enable
// reuse across different request contexts and support background processing
// without HTTP request lifecycle constraints.
//
// Configuration-Driven: All external service configurations (SMTP, cleanup
// intervals) are managed through the central config system, enabling environment
// specific behavior without code changes.
//
// Graceful Degradation: Services are designed to fail gracefully without
// impacting core functionality - email failures are logged but don't prevent
// user operations, and cleanup failures don't affect request processing.
package services
