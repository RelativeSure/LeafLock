FROM node:22-alpine@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9 AS builder

# Add security updates
RUN apk --no-cache add git

WORKDIR /app

# Build arguments with sensible defaults
ARG VITE_API_URL=http://localhost:8080
ARG VITE_ENABLE_ADMIN_PANEL=false
ENV VITE_API_URL=$VITE_API_URL \
    VITE_ENABLE_ADMIN_PANEL=$VITE_ENABLE_ADMIN_PANEL \
    NODE_ENV=production

# Install pnpm
RUN npm install -g pnpm@10.15.1

# Copy package files first for better caching
COPY package.json pnpm-lock.yaml ./

# Install dependencies with frozen lockfile (including dev dependencies for build)
RUN echo "Installing dependencies..." && \
    pnpm install --frozen-lockfile && \
    echo "Dependencies installed successfully"

# Copy source code (excluding files in .dockerignore)
COPY . .

# Debug: Show environment and verify files
RUN echo "Build environment:" && \
    echo "VITE_API_URL=$VITE_API_URL" && \
    echo "VITE_ENABLE_ADMIN_PANEL=$VITE_ENABLE_ADMIN_PANEL" && \
    echo "NODE_ENV=$NODE_ENV" && \
    ls -la src/ && \
    echo "Starting build..."

# Build the application with better error handling
RUN pnpm run build || (echo "Build failed. Checking for common issues..." && \
    echo "Node version: $(node --version)" && \
    echo "PNPM version: $(pnpm --version)" && \
    echo "TypeScript files:" && find src -name "*.ts" -o -name "*.tsx" | head -5 && \
    exit 1)

# Verify build output
RUN echo "Build completed successfully. Output:" && \
    ls -la dist/ && \
    echo "Build artifacts ready"

# Final stage - optimized nginx with faster startup
FROM nginx:1.29-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8

# Install security updates, curl for health checks, and libcap-utils so nginx can bind to 80 as non-root
RUN apk --no-cache add ca-certificates curl libcap-utils && \
    rm -rf /usr/share/nginx/html/* && \
    rm -rf /var/cache/apk/*

# Copy custom nginx config
# Copy nginx template; resolve PORT at startup
COPY nginx.conf.template /etc/nginx/nginx.conf.template

# Copy entrypoint script and ensure it is executable
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Create non-root user and set permissions in one layer for faster startup
RUN addgroup -g 1001 -S nginx-user && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx-user -g nginx-user nginx-user && \
    chown -R nginx-user:nginx-user /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown nginx-user:nginx-user /var/run/nginx.pid

# Allow nginx binary to bind privileged ports even when running as non-root
RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

# Use non-root user for runtime
USER nginx-user

# Default port for Coolify deployment (unprivileged port)
ENV PORT=8080

# Document the listening port for platforms that read EXPOSE  
EXPOSE 8080

# Optimized health check - faster startup and response using curl
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f --max-time 2 --silent http://localhost:${PORT}/health || exit 1

# Explicit entrypoint to generate config then start nginx
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# No CMD needed; entrypoint launches nginx
