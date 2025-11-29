// Package handlers implements the HTTP request processing layer for LeafLock,
// providing RESTful API endpoints for note management, user accounts, collaboration,
// and all client-facing functionality.
//
// # Purpose and Responsibilities
//
// The handlers package serves as the primary interface between HTTP requests and
// the application's business logic, responsible for:
//   - Processing incoming HTTP requests with validation and sanitization
//   - Managing user authentication and authorization checks
//   - Coordinating data access through the database layer
//   - Handling encryption/decryption operations for sensitive data
//   - Generating appropriate HTTP responses with proper status codes
//   - Implementing rate limiting and security headers
//
// # Key Abstractions and Patterns
//
// Handler Pattern: Each domain area (notes, accounts, folders, etc.) has its own
// handler struct with injected dependencies (database, crypto service, config).
// This promotes separation of concerns and testability.
//
// Request/Response DTOs: Each endpoint defines specific structs for request
// validation and response formatting, ensuring type safety and clear API contracts.
//
// Error Handling: Consistent error response format with proper HTTP status codes
// and user-friendly error messages that don't expose internal implementation details.
//
// Encryption Integration: Handlers work with encrypted data transparently,
// delegating cryptographic operations to the crypto package while maintaining
// zero-knowledge principles where appropriate.
//
// # Integration Points
//
// The handlers package integrates with:
//   - database/: All data persistence and retrieval operations
//   - crypto/: Encryption/decryption of sensitive note content and metadata
//   - config/: Application configuration for feature flags and limits
//   - auth/: Authentication middleware and user session management
//   - middleware/: Rate limiting, request ID generation, and security headers
//   - utils/: Logging, validation helpers, and error context management
//
// # Security Considerations
//
//   - All user inputs are validated using struct tags and custom validators
//   - SQL queries are parameterized to prevent injection attacks
//   - Authentication is required for all sensitive operations
//   - Rate limiting is applied to prevent abuse and brute force attacks
//   - CORS and CSRF protection are implemented for cross-origin security
//   - Encryption keys are never logged or exposed in error messages
//   - File uploads are validated for type and size constraints
//
// # Architectural Decisions
//
// Domain-Driven Organization: Handlers are organized by business domain (notes,
// accounts, folders) rather than technical patterns, making the API structure
// intuitive for developers and aligning with RESTful resource modeling.
//
// Dependency Injection: All external dependencies are injected into handlers
// rather than using global state, enabling comprehensive unit testing and
// flexible configuration management.
//
// Zero-Knowledge Architecture: Where possible, handlers operate on encrypted
// data without access to decryption keys, particularly for note content. This
// architectural choice enhances privacy but requires careful design of search
// and collaboration features.
//
// Consistent Error Responses: All handlers return standardized error responses
// with appropriate HTTP status codes, ensuring predictable client behavior and
// proper error handling across the entire API surface.
package handlers
