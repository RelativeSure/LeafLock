# Code Commenting Guidelines for LeafLock

## Overview

This document provides comprehensive guidelines for writing functional and understandable comments in the LeafLock codebase, optimized for both human developers and AI systems.

## Core Principles

### 1. The "Why, Not What" Principle
Comments should explain the reasoning behind code decisions, not just restate what the code does.

**❌ Bad:**
```go
// Check if user is authenticated
if user.IsAuthenticated {
```

**✅ Good:**
```go
// Verify authentication before processing sensitive operations
// This prevents unauthorized access to encrypted note content
if user.IsAuthenticated {
```

### 2. Context and Purpose Documentation
Always provide context about how the code fits into the larger system.

**✅ Good (Go):**
```go
// EncryptWithKeyDerivation implements envelope encryption for note content
// This approach ensures that even if the database is compromised, individual
// notes remain encrypted with user-specific keys derived from the master key
func (c *CryptoService) EncryptWithKeyDerivation(plaintext []byte, keyType string) ([]byte, error) {
```

**✅ Good (TypeScript):**
```typescript
// useAutosave manages automatic saving of note content
// Implements debouncing to prevent excessive API calls while ensuring
// user changes are persisted within 2 seconds of inactivity
export function useAutosave(content: string, noteId: string) {
```

## Backend (Go) Commenting Standards

### Package Documentation
Every package must have a comprehensive package-level comment explaining:
- Primary purpose and responsibilities
- Key abstractions and patterns used
- Integration points with other packages
- Security considerations

**Template:**
```go
// Package [name] provides [primary purpose] for the LeafLock application.
// It implements [key abstractions] to handle [specific responsibilities].
// 
// Key features:
//   - [Feature 1 with purpose]
//   - [Feature 2 with purpose]
// 
// Integration: This package works with [related packages] to [integration purpose].
// Security: [Security considerations and threat model]
package [name]
```

### Function Documentation
Document all exported functions with:
- Purpose and business logic
- Parameter meanings and constraints
- Return value semantics
- Error conditions and handling
- Performance characteristics

**Template:**
```go
// FunctionName performs [specific action] by [approach/algorithm].
// 
// Parameters:
//   - param1: [description and constraints]
//   - param2: [description and constraints]
// 
// Returns:
//   - [description of return value]
//   - Error: [specific error conditions and meanings]
// 
// Performance: [time/space complexity if relevant]
// Thread-safety: [concurrency considerations]
func FunctionName(param1 type1, param2 type2) (returnType, error) {
```

### Complex Logic Documentation
For non-trivial algorithms, business rules, or optimizations:

```go
// Implement exponential backoff for database connection retries
// This prevents thundering herd problems when the database comes back online
// after an outage. Jitter is added to prevent synchronized retry attempts
// across multiple application instances.
// 
// Backoff sequence: 1s, 2s, 4s, 8s, 16s (max 5 retries)
// Jitter: ±25% random variation to prevent alignment
for attempt := 0; attempt < maxRetries; attempt++ {
    backoffDuration := time.Duration(math.Pow(2, float64(attempt))) * time.Second
    jitter := time.Duration(rand.Float64()*0.5-0.25) * backoffDuration
    time.Sleep(backoffDuration + jitter)
```

## Frontend (TypeScript/React) Commenting Standards

### Component Documentation
Document React components with:
- Purpose and user experience goals
- Props interface and their effects
- State management approach
- Side effects and lifecycle considerations
- Accessibility considerations

**Template:**
```typescript
/**
 * ComponentName - [Brief description of what the component does]
 * 
 * @purpose [Detailed explanation of the component's role in the UI/UX]
 * @ux [User experience goals and behavior]
 * @a11y [Accessibility considerations and ARIA usage]
 * 
 * @param props - Component properties
 * @param props.[name] - [Detailed description of each prop's purpose and effect]
 * 
 * @example
 * ```tsx
 * <ComponentName 
 *   prop1="value1" 
 *   prop2={callback}
 * />
 * ```
 */
export function ComponentName({ prop1, prop2 }: ComponentProps) {
```

### Store Documentation
Document state management with:
- Store purpose and responsibilities
- State structure and relationships
- Action semantics and side effects
- Persistence strategy
- Synchronization considerations

**Template:**
```typescript
/**
 * [StoreName]Store - Manages [specific domain] state for the application
 * 
 * Responsibilities:
 * - [Specific responsibility 1]
 * - [Specific responsibility 2]
 * 
 * State Structure:
 * - [Property]: [Purpose and relationship to other state]
 * 
 * Persistence: [How/when state is persisted]
 * Synchronization: [How state stays synchronized with backend/API]
 */
interface [StoreName]Store {
```

### Hook Documentation
Document custom hooks with:
- Purpose and use cases
- Parameters and their effects
- Return value structure and semantics
- Side effects and cleanup
- Performance considerations

**Template:**
```typescript
/**
 * useHookName - [Brief description]
 * 
 * Purpose: [Detailed explanation of what the hook accomplishes]
 * 
 * @param param1 - [Description and constraints]
 * @param param2 - [Description and constraints]
 * 
 * @returns Object containing:
 *   - property1: [Description and usage]
 *   - property2: [Description and usage]
 * 
 * @sideEffects [Any effects outside the component]
 * @cleanup [Cleanup requirements]
 * @performance [Performance considerations and optimizations]
 */
export function useHookName(param1: type1, param2: type2) {
```

## Security-Specific Documentation

### Cryptographic Operations
Always document:
- Algorithm choices and rationale
- Key management approach
- Security assumptions and threat model
- Compliance considerations

**Example:**
```go
// EncryptNoteContent implements authenticated encryption for user notes
// using XChaCha20-Poly1305 AEAD cipher. This provides:
// - Confidentiality: Content encrypted with unique per-note key
// - Authenticity: Poly1305 authentication tag prevents tampering
// - Integrity: Any modification detected during decryption
// 
// Key derivation: Uses HKDF-SHA256 with server master key and note-specific salt
// Nonce generation: 192-bit random nonce for each encryption operation
// Threat model: Protects against database compromise and network eavesdropping
func EncryptNoteContent(content []byte, key []byte) ([]byte, error) {
```

### Authentication/Authorization
Document:
- Authentication flow and token management
- Permission checking logic
- Session handling and timeout behavior
- Security boundaries and trust levels

## AI-Specific Considerations

### Context for AI Understanding
Include comments that help AI systems understand:
- Data flow between components
- Business rule dependencies
- Error handling strategies
- Performance optimization rationale

**Example:**
```typescript
// NoteEditor component implements a complex state synchronization pattern
// between local editor state and global application state. This pattern:
// 1. Maintains local draft state to prevent unnecessary re-renders
// 2. Syncs with global state on blur events and periodic intervals
// 3. Handles conflict resolution when remote changes occur during editing
// 4. Implements optimistic updates for better perceived performance
// 
// State flow: localEditor -> debounce -> validate -> encrypt -> globalStore -> API
// Conflict resolution: Last-write-wins with timestamp comparison
// Error recovery: Falls back to last known good state on sync failure
```

### Cross-Component Relationships
Document how different parts of the system interact:

```go
// CleanupService orchestrates data lifecycle management across the application
// 
// Integration points:
// - Database layer: Removes expired records and optimizes storage
// - File storage: Cleans up orphaned encrypted note content
// - Cache layer: Invalidates stale entries in Redis
// - Audit trail: Maintains cleanup logs for compliance
// 
// Triggered by: Scheduled jobs, admin API calls, storage threshold alerts
// Coordinates with: NoteService, UserService, AuditService
```

## Comment Quality Checklist

Before committing code, ensure comments:

- [ ] Explain the "why" behind decisions, not just the "what"
- [ ] Provide context about system integration and data flow
- [ ] Document security considerations and threat models
- [ ] Include examples for complex functions and APIs
- [ ] Explain performance optimizations and trade-offs
- [ ] Describe error handling strategies and edge cases
- [ ] Document business rules and constraints
- [ ] Include accessibility considerations for UI components
- [ ] Provide enough context for AI systems to understand relationships
- [ ] Follow consistent formatting and style within each language

## Tools and Automation

### Comment Validation
Use these tools to maintain comment quality:

1. **Go**: `golint` and `go vet` for documentation standards
2. **TypeScript**: ESLint with JSDoc validation rules
3. **Pre-commit hooks**: Validate comment completeness for new functions

### Documentation Generation
- Go: Use `godoc` for API documentation
- TypeScript: Use TypeDoc for component documentation
- Swagger: Maintain up-to-date API documentation

## Review Process

During code review, pay special attention to:
1. Comments that explain complex business logic
2. Security-related documentation
3. Cross-component interaction documentation
4. Error handling and edge case explanations
5. Performance optimization rationale

Comments should be reviewed with the same rigor as code, as they are critical for maintainability and AI-assisted development.