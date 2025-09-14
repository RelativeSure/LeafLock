FROM node:22-alpine@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9 AS builder

# Add security updates
RUN apk --no-cache add git

WORKDIR /app
ARG VITE_API_URL
ARG VITE_ENABLE_ADMIN_PANEL
ENV VITE_API_URL=$VITE_API_URL \
    VITE_ENABLE_ADMIN_PANEL=$VITE_ENABLE_ADMIN_PANEL

# Install pnpm
RUN npm install -g pnpm@10.15.1

# Copy package files first for better caching
COPY package.json pnpm-lock.yaml ./

# Install dependencies with frozen lockfile (including dev dependencies for build)
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the application
RUN pnpm run build

# Final stage - optimized nginx
FROM nginx:1.29-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8

# Install security updates
RUN apk --no-cache add ca-certificates

# Remove default nginx website
RUN rm -rf /usr/share/nginx/html/*

# Copy custom nginx config
# Copy nginx template; resolve PORT at startup
COPY nginx.conf.template /etc/nginx/nginx.conf.template

# Copy built application
COPY --from=builder /app/dist /usr/share/nginx/html

# Create non-root user for nginx
RUN addgroup -g 1001 -S nginx-user && \
    adduser -S -D -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx-user -g nginx-user nginx-user

# Set proper permissions
RUN chown -R nginx-user:nginx-user /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d
RUN touch /var/run/nginx.pid && chown -R nginx-user:nginx-user /var/run/nginx.pid

# Use non-root user
USER nginx-user

# Default port if not provided by platform
ENV PORT=8080

# Health check (uses resolved PORT)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/ || exit 1

# Start nginx with PORT substitution
CMD ["/bin/sh", "-c", ": \${PORT:=8080}; envsubst '$$PORT' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf && exec nginx -g 'daemon off;'"]
