FROM node:20-alpine AS builder

# Add security updates
RUN apk --no-cache add git

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies with clean install
RUN npm ci --only=production --no-audit --no-fund

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Final stage - optimized nginx
FROM nginx:1.25-alpine

# Install security updates
RUN apk --no-cache add ca-certificates

# Remove default nginx website
RUN rm -rf /usr/share/nginx/html/*

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

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

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
