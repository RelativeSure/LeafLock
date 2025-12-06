// Package utils provides shared utilities and cross-cutting concerns for the
// LeafLock application, implementing common functionality used across handlers,
// services, and other packages.
//
// # Purpose and Responsibilities
//
// The utils package serves as a shared library for common operations that don't
// warrant separate packages, including:
//   - Structured logging with configurable log levels and output destinations
//   - Request context management for storing client metadata
//   - Network utilities for IP extraction and validation
//   - Input validation functions for common data formats
//   - Error context wrapping for improved debugging
//   - Helper functions for database null value handling
//
// # Key Abstractions and Patterns
//
// Logger Pattern: Multiple logger instances (Debug, Info, Warn, Error) with
// configurable log levels enable fine-grained control over logging verbosity
// in different environments.
//
// Context Keys: Type-safe context keys prevent key collisions when storing
// request-scoped data like client IP addresses and user agent strings.
//
// Validation Functions: Pure functions for validating common formats (hex colors,
// email addresses) provide reusable validation logic across the application.
//
// Error Wrapping: Context-aware error wrapping preserves error chains while
// adding operational context for better debugging and monitoring.
//
// # Integration Points
//
// The utils package is used by:
//   - handlers/: Request logging, validation, and error context management
//   - middleware/: IP extraction and request ID handling
//   - services/: Background logging and error reporting
//   - websocket/: Connection logging and client identification
//   - main/: Application initialization and configuration logging
//
// # Security Considerations
//   - Log messages are sanitized to prevent log injection attacks
//   - Client IP extraction handles proxy headers safely
//   - Sensitive data is never logged or included in error messages
//   - Validation functions prevent malformed data from propagating
//   - Context data is scoped to prevent information leakage between requests
//
// # Architectural Decisions
//
// Minimal Dependencies: Utils intentionally has minimal external dependencies
// to remain lightweight and avoid circular dependencies between packages.
//
// Global Logger State: While generally avoiding global state, logging uses
// package-level variables for convenience since logging is a cross-cutting
// concern used throughout the application.
//
// Function-Based Design: Rather than creating complex types, utils provides
// simple functions that can be easily composed and tested, following the
// principle of doing one thing well.
//
// No Business Logic: Utils contains only generic, reusable functionality
// without any business-specific logic, ensuring it remains applicable across
// different contexts and use cases.
package utils
