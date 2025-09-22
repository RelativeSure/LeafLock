FROM oven/bun:latest

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package.json ./
# Only copy lockfile if it exists, otherwise install normally
COPY bun.lockb* ./
RUN if [ -f bun.lockb ]; then bun install --frozen-lockfile --production; else bun install --production; fi

# Copy source code and content
COPY src/ ./src/
COPY content/ ./content/
COPY public/ ./public/
COPY tsconfig.json ./

# Build the application
RUN bun run build

# Create non-root user
RUN addgroup --system --gid 1001 bunuser
RUN adduser --system --uid 1001 bunuser
USER bunuser

# Expose port
EXPOSE 3000

# Health check - use the dedicated health endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Start the application
CMD ["bun", "run", "start"]