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
    ./entrypoint.go && \
    chmod +x /app/entrypoint

# Final stage - minimal runtime
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create non-root user structure
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy the binaries with explicit execute permissions
COPY --from=builder --chmod=0755 /app/main /app/main
COPY --from=builder --chmod=0755 /app/entrypoint /app/entrypoint

# Set user to non-root
USER nobody:nogroup

# Expose port
EXPOSE 8080

# Health check will be handled by docker-compose

# Explicit entrypoint wrapper handles env defaults then execs main
ENV BACKEND_BINARY=/app/main
ENTRYPOINT ["/app/entrypoint"]
