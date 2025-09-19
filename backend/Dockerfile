FROM golang:1.25-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

# Add security updates and build tools
RUN apk --no-cache add git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with optimizations and security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main .

# Ensure the binary is executable in the builder layer (belt-and-suspenders)
RUN chmod +x /app/main

# Build a tiny entrypoint that sets defaults and execs the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -trimpath \
    -o /app/entrypoint \
    ./cmd/entrypoint && \
    chmod +x /app/entrypoint

# Final stage - minimal runtime with shell support for health checks
FROM alpine:3.20@sha256:b3119ef930faabb6b7b976780c0c7a9c1aa24d0c75e9179ac10e6bc9ac080d0d

# Install runtime dependencies and curl so Docker health checks can probe HTTP
RUN apk --no-cache add ca-certificates tzdata curl

# Copy binaries from builder with explicit execute permissions
COPY --from=builder --chmod=0755 /app/main /app/main
COPY --from=builder --chmod=0755 /app/entrypoint /app/entrypoint

# Create application user to avoid running as root
RUN addgroup -g 1001 -S app && \
    adduser -S -D -H -u 1001 -s /sbin/nologin -G app app

# Ensure binary directory is owned by app user
RUN chown -R app:app /app

# Set user to non-root
USER app

# Expose port
EXPOSE 8080

# Health check will be handled by docker-compose

# Explicit entrypoint wrapper handles env defaults then execs main
ENV BACKEND_BINARY=/app/main
ENTRYPOINT ["/app/entrypoint"]
