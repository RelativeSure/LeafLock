// Package websocket implements real-time collaboration features for LeafLock,
// enabling multiple users to simultaneously edit and view notes with live updates
// and conflict resolution.
//
// # Purpose and Responsibilities
//
// The websocket package provides the real-time communication infrastructure
// necessary for collaborative note editing, responsible for:
//   - Managing WebSocket connection lifecycle and authentication
//   - Broadcasting note changes to all connected collaborators in real-time
//   - Implementing operational transformation for conflict resolution
//   - Maintaining presence information (who is currently viewing/editing)
//   - Handling connection failures and automatic reconnection scenarios
//   - Ensuring data consistency across multiple concurrent editors
//
// # Key Abstractions and Patterns
//
// Hub Pattern: A central Hub manages all active WebSocket connections,
// coordinating message broadcasting and maintaining connection state. This
// pattern enables efficient message routing and connection management.
//
// Connection Abstraction: Each WebSocket connection is wrapped in a Connection
// struct that manages the bidirectional communication channel and associates
// users with specific notes they're collaborating on.
//
// Message Protocol: Structured message types support different collaboration
// operations (cursor movement, text changes, user presence) with versioning
// for conflict detection and resolution.
//
// JWT Authentication: WebSocket connections are authenticated using the same
// JWT tokens as HTTP requests, ensuring consistent security across transport
// mechanisms.
//
// # Integration Points
//
// The websocket package integrates with:
//   - handlers/: HTTP upgrade requests and authentication token validation
//   - database/: Persistence of collaboration state and conflict resolution
//   - auth/: JWT token validation and user authentication
//   - config/: WebSocket-specific configuration like message size limits
//   - crypto/: Encryption of collaborative messages when necessary
//
// # Security Considerations
//
//   - All WebSocket connections require valid JWT authentication
//   - Users can only connect to notes they have permission to access
//   - Message size limits prevent resource exhaustion attacks
//   - Connection rate limiting prevents WebSocket flooding
//   - Origin validation ensures connections come from authorized domains
//   - User actions are validated against their permissions before broadcasting
//   - Encrypted notes maintain encryption during collaboration sessions
//
// # Architectural Decisions
//
// WebSocket-First Design: Rather than implementing collaborative features over
// HTTP polling, the architecture uses WebSockets for true real-time communication
// with lower latency and better resource utilization.
//
// Server-Side State Management: The Hub maintains connection state server-side
// rather than relying on client-side coordination, enabling better consistency
// and simpler client implementations.
//
// Operational Transformation: For conflict resolution, the system uses operational
// transformation rather than simple locking, allowing multiple users to edit
// simultaneously while maintaining data consistency.
//
// Separate Transport Layer: WebSocket functionality is isolated in its own
// package rather than being mixed with HTTP handlers, enabling clear separation
// of concerns and independent scaling of real-time features.
//
// Privacy-Preserving Collaboration: The architecture supports encrypted
// collaboration where the server facilitates real-time updates without access
// to the actual note content, maintaining zero-knowledge principles.
package websocket